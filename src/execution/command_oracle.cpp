#include <a64dispatch/execution.hpp>
#include <a64dispatch/process.hpp>
#include <algorithm>
#include <cctype>
namespace a64dispatch {
namespace {
void substitute(std::string &argument, const std::string &key,
                const std::string &value) {
  std::size_t start = 0;
  while ((start = argument.find(key, start)) != std::string::npos) {
    argument.replace(start, key.size(), value);
    start += value.size();
  }
}
} // namespace
Json execution_json(const ExecutionResult &result) {
  Json coverage = Json::array(), states = Json::object(),
       edges = Json::object();
  for (auto address : result.executed)
    coverage.push_back(hex_address(address));
  for (const auto &[source, destinations] : result.control_edges) {
    auto &values = edges[hex_address(source)] = Json::array();
    for (auto target : destinations)
      values.push_back(hex_address(target));
  }
  for (const auto &[site, values] : result.state_targets) {
    auto &entries = states[hex_address(site)] = Json::object();
    for (const auto &[state, targets] : values) {
      auto &destinations = entries[hex_address(state)] = Json::array();
      for (auto target : targets)
        destinations.push_back(hex_address(target));
    }
  }
  return {{"output", hex_bytes(result.output)},
          {"returned", hex_address(result.returned)},
          {"instructions", result.instructions},
          {"observations", result.observations.json()},
          {"coverage", coverage},
          {"control_edges", edges},
          {"state_targets", states}};
}
ExecutionResult execution_from_json(const Json &record,
                                    const CodeImage &image) {
  ExecutionResult result;
  result.output = parse_hex(record.at("output"));
  if (result.output.size() > 1024 * 1024)
    throw AnalysisError("oracle response output limit exceeded");
  result.returned = parse_address(record.at("returned"));
  result.instructions = parse_address(record.at("instructions"));
  if (result.instructions == 0 || result.instructions > 100000000)
    throw AnalysisError("oracle response has invalid instruction count");
  result.observations.merge(record.at("observations"));
  const auto &coverage = record.at("coverage");
  if (!coverage.is_array() || coverage.empty() || coverage.size() > 1000000)
    throw AnalysisError(
        "oracle response requires bounded instruction coverage");
  for (const auto &address : coverage) {
    auto point = parse_address(address);
    if (!image.instruction(point))
      throw AnalysisError("oracle coverage contains an unmapped instruction");
    result.executed.insert(point);
  }
  const auto edges = record.value("control_edges", Json::object());
  if (!edges.is_object() || edges.size() > 1000000)
    throw AnalysisError("invalid executed control-edge table");
  std::size_t edge_count = 0;
  for (const auto &[source, destinations] : edges.items()) {
    auto address = parse_address(Json(source));
    if (!image.instruction(address) || !destinations.is_array() ||
        destinations.size() > 65536)
      throw AnalysisError("invalid executed control edge");
    for (const auto &target : destinations) {
      if (++edge_count > 2000000)
        throw AnalysisError("executed edge count limit exceeded");
      const auto destination = parse_address(target);
      if (destination % 4)
        throw AnalysisError("executed edge target is not aligned");
      result.control_edges[address].insert(destination);
    }
  }
  const auto &states = record.value("state_targets", Json::object());
  if (!states.is_object() || states.size() > 65536)
    throw AnalysisError("invalid observed-state table");
  std::size_t values = 0;
  for (const auto &[site, entries] : states.items()) {
    auto branch = parse_address(Json(site));
    if (!image.instruction(branch) || !entries.is_object())
      throw AnalysisError("invalid observed-state site");
    for (const auto &[state, targets] : entries.items()) {
      if (++values > 1000000 || !targets.is_array() || targets.size() > 65536)
        throw AnalysisError("observed-state count limit exceeded");
      for (const auto &target : targets)
        result.state_targets[branch][parse_address(Json(state))].insert(
            parse_address(target));
    }
  }
  return result;
}
ExecutionResult command_execution(const Json &specification,
                                  const CodeImage &image, Address entry,
                                  std::span<const std::uint8_t> input,
                                  const std::vector<DispatchSite> &sites) {
  TemporaryDirectory temporary;
  auto image_path = temporary.path() / "image.json";
  write_document(image_path, image.snapshot());
  auto fingerprint = image.fingerprint();
  std::vector<std::string> arguments;
  auto command = specification.at("command");
  if (!command.is_array() || command.empty())
    throw AnalysisError("command backend requires an argv array");
  bool image_argument = false;
  for (const auto &argument : command) {
    auto text = argument.get<std::string>();
    image_argument =
        image_argument || text.find("{image}") != std::string::npos;
    substitute(text, "{image}", image_path.string());
    substitute(text, "{entry}", hex_address(entry));
    substitute(text, "{image_sha256}", fingerprint);
    arguments.push_back(std::move(text));
  }
  auto protocol = specification.value("protocol", std::string("json"));
  ByteArray payload;
  if (protocol == "json") {
    Json descriptors = Json::array();
    for (const auto &site : sites)
      descriptors.push_back(site_json(site));
    auto parameters = specification;
    parameters.erase("command");
    parameters.erase("known_vectors");
    parameters.erase("protocol");
    parameters["backend"] = "unicorn";
    Json request = {
        {"protocol_version", 1},       {"image_path", image_path.string()},
        {"image_sha256", fingerprint}, {"entry", hex_address(entry)},
        {"input", hex_bytes(input)},   {"execution", parameters},
        {"sites", descriptors}};
    auto text = request.dump();
    payload.assign(text.begin(), text.end());
  } else if (protocol == "bytes" || protocol == "hex") {
    if (!image_argument)
      throw AnalysisError(
          "raw oracle command must receive an {image} argument");
    if (protocol == "hex") {
      auto text = hex_bytes(input) + "\n";
      payload.assign(text.begin(), text.end());
    } else
      payload.assign(input.begin(), input.end());
  } else
    throw AnalysisError("unknown command oracle protocol");
  auto timeout = parse_address(
      specification.value("command_timeout_milliseconds", Json(30000u)));
  if (timeout == 0 || timeout > 60000)
    throw AnalysisError("command timeout must be 1..60000 milliseconds");
  auto process =
      run_process(arguments, payload, static_cast<unsigned>(timeout));
  if (process.exit_code != 0)
    throw AnalysisError(
        "oracle command failed with status " +
        std::to_string(process.exit_code) + ": " +
        std::string(process.errors.begin(), process.errors.end()));
  if (protocol != "json") {
    ExecutionResult result;
    if (protocol == "hex") {
      std::string encoded(process.output.begin(), process.output.end());
      std::erase_if(encoded, [](unsigned char character) {
        return std::isspace(character) != 0;
      });
      if (encoded.starts_with("0x") || encoded.starts_with("0X"))
        encoded.erase(0, 2);
      result.output = parse_hex(encoded);
    } else
      result.output = process.output;
    if (result.output.size() > 1024 * 1024)
      throw AnalysisError("raw oracle output exceeds one MiB");
    return result;
  }
  auto response = parse_document(process.output);
  if (response.at("protocol_version") != 1 ||
      response.at("image_sha256") != fingerprint ||
      parse_address(response.at("entry")) != entry)
    throw AnalysisError("oracle response does not identify the requested "
                        "candidate image and entry");
  if (!response.value("completed", false))
    throw AnalysisError("oracle response did not complete execution");
  return execution_from_json(response.at("result"), image);
}
} // namespace a64dispatch
