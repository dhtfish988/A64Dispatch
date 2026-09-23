#include <a64dispatch/execution.hpp>
#include <iostream>
using namespace a64dispatch;
int main(int argc, char **argv) {
  try {
    if (argc > 1 && std::string(argv[1]) == "--help") {
      std::cout << "a64-oracle-worker reads one protocol-v1 JSON request on "
                   "stdin and executes the supplied snapshot with Unicorn.\n";
      return 0;
    }
    ByteArray bytes;
    char buffer[4096];
    while (std::cin) {
      std::cin.read(buffer, sizeof(buffer));
      auto count = std::cin.gcount();
      if (count > 0) {
        if (bytes.size() + static_cast<std::size_t>(count) > 8 * 1024 * 1024)
          throw AnalysisError("request size limit exceeded");
        bytes.insert(bytes.end(), buffer, buffer + count);
      }
    }
    auto request = parse_document(bytes);
    if (request.at("protocol_version") != 1)
      throw AnalysisError("unsupported oracle protocol");
    auto image = CodeImage::load(request.at("image_path").get<std::string>());
    if (image.fingerprint() != request.at("image_sha256").get<std::string>())
      throw AnalysisError("request image hash mismatch");
    auto entry = parse_address(request.at("entry"));
    auto input = parse_hex(request.at("input"));
    auto specification = request.at("execution");
    specification["backend"] = "unicorn";
    std::vector<DispatchSite> sites;
    for (const auto &value : request.at("sites"))
      sites.push_back(site_from_json(value));
    ExecutionOracle oracle(specification);
    auto result = oracle.run(image, entry, input, sites);
    Json response = {{"protocol_version", 1},
                     {"image_sha256", image.fingerprint()},
                     {"entry", hex_address(entry)},
                     {"completed", true},
                     {"result", execution_json(result)}};
    std::cout << response.dump() << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "oracle-worker: " << error.what() << '\n';
    return 2;
  }
}
