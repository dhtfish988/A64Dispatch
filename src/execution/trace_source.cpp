#include <a64dispatch/execution.hpp>
#include <a64dispatch/process.hpp>
namespace a64dispatch {
Json collect_external_trace(const CodeImage &image, const Json &configuration) {
  if (!configuration.is_object())
    throw AnalysisError("trace_command requires an object");
  const auto &command = configuration.at("argv");
  if (!command.is_array() || command.empty() || command.size() > 256)
    throw AnalysisError("trace_command.argv requires 1..256 arguments");
  const auto timeout =
      parse_address(configuration.value("timeout_milliseconds", Json(30000)));
  if (!timeout || timeout > 60000)
    throw AnalysisError("trace timeout must be in 1..60000 milliseconds");
  TemporaryDirectory temporary;
  const auto path = temporary.path() / "source.json";
  write_document(path, image.snapshot());
  const auto fingerprint = image.fingerprint();
  const auto entry =
      parse_address(configuration.value("entry", Json(image.entry)));
  std::vector<std::string> arguments;
  for (const auto &item : command) {
    auto value = item.get<std::string>();
    for (const auto &[key, replacement] :
         std::map<std::string, std::string>{{"{image}", path.string()},
                                            {"{image_sha256}", fingerprint},
                                            {"{entry}", hex_address(entry)}}) {
      std::size_t position = 0;
      while ((position = value.find(key, position)) != std::string::npos) {
        value.replace(position, key.size(), replacement);
        position += replacement.size();
      }
    }
    arguments.push_back(std::move(value));
  }
  const auto payload = Json({{"protocol_version", 1},
                             {"source_sha256", fingerprint},
                             {"image_path", path.string()},
                             {"entry", hex_address(entry)}})
                           .dump();
  auto response = run_process(
      arguments,
      {reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()},
      static_cast<unsigned>(timeout));
  if (response.exit_code)
    throw AnalysisError("trace command exited unsuccessfully: " +
                        std::to_string(response.exit_code));
  auto document = parse_document(response.output);
  if (!document.is_object() ||
      document.at("source_sha256").get<std::string>() != fingerprint)
    throw AnalysisError("trace command response belongs to a different image");
  ObservationSet observations;
  observations.merge(document.at("observations"));
  return observations.json();
}
} // namespace a64dispatch
