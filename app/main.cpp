#include <a64dispatch/workflow.hpp>
#include <iostream>
#include <map>
#include <set>
using namespace a64dispatch;
namespace {
const char *help = R"(A64Dispatch — AArch64 analysis and verified rewriting
  a64-dispatch COMMAND --image IMAGE --config CONFIG [OPTIONS]
  a64-dispatch snapshot IMAGE [OUTPUT]
  a64-dispatch decode WORD [ADDRESS]
Commands:
  survey, classify, resolve, plan  Generate source-bound analysis stages
  preview, run                    Candidate image (run --apply to apply)
  graph                           Graph edges (use --apply to apply)
  cleanup                         Propose literal/BLR and short filler changes
  trace                           Execute and observe known vectors
  verify                          Verify proposed or --current candidate
  regress                         Verify, restore, and regenerate all proposals
  restore                         Restore a matching applied --from receipt
  discover                        Group work by function
  batch                           Independent per-group results (optional --apply)
Options:
  --output FILE     Atomically write JSON (otherwise stdout)
  --from FILE       Check a prior stage artifact; required for restore
  --current FILE    Current snapshot/result envelope for verify or restore
  --function NAME   Select a function entry address or unambiguous name
  --apply           Return an applied snapshot; preserve all input files
  --dry-run         Explicit preview; incompatible with --apply
IMAGE may be set as `image` in CONFIG, relative to that file.
CONFIG: JSON/YAML, executable_regions, mode (default graph), analysis,
observations/trace_files, execution and known_vectors.
Aliases: census=survey, apply=run, switch=graph, revert=restore, clean=cleanup.
The apply alias still needs --apply to apply changes to the output snapshot.
Exit: 0 completed, 1 verification failed, 2 invalid input/execution error.
)";
struct Arguments {
  std::string command;
  std::map<std::string, std::string> values;
  bool apply = false, dry = false;
};
Arguments arguments(int argc, char **argv) {
  Arguments result;
  result.command = argv[1];
  const std::map<std::string, std::string> aliases{{"census", "survey"},
                                                   {"apply", "run"},
                                                   {"switch", "graph"},
                                                   {"revert", "restore"},
                                                   {"clean", "cleanup"}};
  if (auto found = aliases.find(result.command); found != aliases.end())
    result.command = found->second;
  const std::set<std::string> options{"--image", "--config",  "--output",
                                      "--from",  "--current", "--function"};
  std::set<std::string> seen;
  for (int index = 2; index < argc; ++index) {
    const std::string key = argv[index];
    if (!seen.insert(key).second)
      throw AnalysisError("duplicate option: " + key);
    if (key == "--apply")
      result.apply = true;
    else if (key == "--dry-run")
      result.dry = true;
    else if (options.contains(key)) {
      if (++index == argc)
        throw AnalysisError("missing value for " + key);
      result.values[key] = argv[index];
    } else
      throw AnalysisError("unknown option: " + key);
  }
  if (result.apply && result.dry)
    throw AnalysisError("--apply and --dry-run are mutually exclusive");
  if (!result.values.contains("--config"))
    throw AnalysisError("--config is required");
  return result;
}
std::filesystem::path resolved(const std::filesystem::path &path,
                               const std::filesystem::path &base) {
  return std::filesystem::weakly_canonical(path.is_absolute() ? path
                                                              : base / path);
}
void guard_output(const std::filesystem::path &output,
                  const std::vector<std::filesystem::path> &inputs) {
  const auto canonical = std::filesystem::weakly_canonical(output);
  for (const auto &input : inputs) {
    if (canonical == std::filesystem::weakly_canonical(input))
      throw AnalysisError(
          "output must not replace an input or configuration file");
    std::error_code error;
    if (std::filesystem::exists(output) &&
        std::filesystem::equivalent(output, input, error) && !error)
      throw AnalysisError("output aliases an input file");
  }
}
CodeImage load_current(const std::filesystem::path &path) {
  auto bytes = read_file(path);
  if (bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' &&
      bytes[2] == 'L' && bytes[3] == 'F')
    return CodeImage::from_elf(bytes);
  auto document = read_document(path);
  return CodeImage::from_snapshot(
      document.contains("image") ? document.at("image") : document);
}
int run(int argc, char **argv) {
  if (argc == 1 || std::string(argv[1]) == "--help") {
    std::cout << help;
    return argc == 1 ? 2 : 0;
  }
  if (std::string(argv[1]) == "--version" && argc == 2) {
    std::cout << "A64Dispatch 1.0.0\n";
    return 0;
  }
  const std::string command = argv[1];
  if (command == "snapshot" && (argc == 3 || argc == 4)) {
    auto image = CodeImage::load(argv[2]);
    if (argc == 4) {
      guard_output(argv[3], {argv[2]});
      write_document(argv[3], image.snapshot());
    } else
      std::cout << image.snapshot().dump(2) << '\n';
    return 0;
  }
  if (command == "decode" && (argc == 3 || argc == 4)) {
    auto raw = parse_address(Json(argv[2]));
    if (raw > 0xffffffff)
      throw AnalysisError("instruction exceeds 32 bits");
    auto address = argc == 4 ? parse_address(Json(argv[3])) : 0x100000;
    InstructionDecoder decoder;
    const auto instruction =
        decoder.decode(address, static_cast<std::uint32_t>(raw));
    std::cout << Json({{"address", hex_address(address)},
                       {"word", hex_address(raw)},
                       {"valid", instruction.valid},
                       {"operation", operation_name(instruction.operation)},
                       {"text", instruction.text},
                       {"width", instruction.width},
                       {"destination", instruction.destination},
                       {"left", instruction.left},
                       {"right", instruction.right},
                       {"condition", instruction.condition},
                       {"flags_written", instruction.flags_written},
                       {"flags_read", instruction.flags_read},
                       {"written_registers", instruction.written.to_string()},
                       {"target", instruction.target
                                      ? Json(hex_address(*instruction.target))
                                      : Json(nullptr)},
                       {"immediate",
                        instruction.immediate
                            ? Json(hex_address(*instruction.immediate))
                            : Json(nullptr)}})
                     .dump(2)
              << '\n';
    return instruction.valid ? 0 : 1;
  }
  auto options = arguments(argc, argv);
  auto config_path =
      resolved(options.values.at("--config"), std::filesystem::current_path());
  auto config = read_document(config_path);
  std::vector<std::filesystem::path> inputs{config_path};
  auto image_path = options.values.contains("--image")
                        ? resolved(options.values.at("--image"),
                                   std::filesystem::current_path())
                        : resolved(config.at("image").get<std::string>(),
                                   config_path.parent_path());
  inputs.push_back(image_path);
  auto input_image =
      config.contains("flat")
          ? CodeImage::from_flat(read_file(image_path), config.at("flat"))
          : CodeImage::load(image_path);
  input_image.origin = image_path.string();
  config.erase("image");
  if (config.contains("trace_files")) {
    ObservationSet combined;
    if (config.contains("observations"))
      combined.merge(config.at("observations"));
    const auto traces = config.at("trace_files");
    if (!traces.is_array() || traces.size() > 256)
      throw AnalysisError("trace_files requires at most 256 paths");
    for (const auto &trace : traces) {
      auto path = resolved(trace.get<std::string>(), config_path.parent_path());
      inputs.push_back(path);
      auto document = read_document(path);
      if (document.contains("source_sha256") &&
          document.at("source_sha256").get<std::string>() !=
              input_image.fingerprint())
        throw AnalysisError("trace artifact belongs to a different image");
      combined.merge(document.contains("observations")
                         ? document.at("observations")
                         : document);
    }
    config["observations"] = combined.json();
    config.erase("trace_files");
  }
  if (options.values.contains("--function"))
    config["functions"] = Json::array({options.values.at("--function")});
  if (config.contains("execution") && config["execution"].contains("command")) {
    auto &argv_list = config["execution"]["command"];
    if (!argv_list.is_array() || argv_list.empty())
      throw AnalysisError("execution.command requires a nonempty argv array");
    auto program = argv_list[0].get<std::string>();
    if (program.find('/') != std::string::npos)
      argv_list[0] = resolved(program, config_path.parent_path()).string();
  }
  if (config.contains("trace_command")) {
    auto &argv_list = config["trace_command"]["argv"];
    if (!argv_list.is_array() || argv_list.empty())
      throw AnalysisError("trace_command.argv requires a nonempty argv array");
    const auto program = argv_list[0].get<std::string>();
    if (program.find('/') != std::string::npos)
      argv_list[0] = resolved(program, config_path.parent_path()).string();
  }
  AnalysisWorkflow workflow(std::move(input_image), config);
  std::optional<Json> prior;
  if (options.values.contains("--from")) {
    inputs.push_back(options.values.at("--from"));
    prior = read_document(options.values.at("--from"));
    if (options.command != "restore")
      workflow.check_artifact(*prior);
  }
  std::optional<CodeImage> current;
  if (options.values.contains("--current")) {
    if (options.command != "verify" && options.command != "restore")
      throw AnalysisError("--current is only valid for verify and restore");
    inputs.push_back(options.values.at("--current"));
    current = load_current(options.values.at("--current"));
  }
  if (options.values.contains("--output"))
    guard_output(options.values.at("--output"), inputs);
  Json output;
  if (options.command == "restore") {
    if (!prior)
      throw AnalysisError("restore requires --from an applied receipt");
    if (options.apply)
      throw AnalysisError("restore emits a restored snapshot without --apply");
    output = workflow.restore(*prior, current ? &*current : nullptr);
    if (options.dry) {
      output["restored"] = false;
      output["preview"] = true;
      output["removed_edges"] = Json::array();
    }
  } else
    output = workflow.execute(options.command, options.apply,
                              current ? &*current : nullptr);
  if (options.values.contains("--output"))
    write_document(options.values.at("--output"), output);
  else
    std::cout << output.dump(2) << '\n';
  return output.contains("passed") && !output.at("passed").get<bool>() ? 1 : 0;
}
} // namespace
int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception &error) {
    std::cerr << "a64-dispatch: " << error.what() << '\n';
    return 2;
  }
}
