#include <a64dispatch/rewrite.hpp>
namespace {
void exercise(a64dispatch::CodeImage image) {
  using namespace a64dispatch;
  std::size_t size = 0;
  AnalysisSettings settings;
  for (const auto &region : image.regions) {
    size += region.bytes.size();
    if (region.executable)
      settings.ranges.emplace_back(region.begin, region.end());
  }
  if (size > 65536 || image.functions.size() > 64)
    return;
  settings.lookback = 16;
  settings.raw["analysis"]["state_expansion"] = {{"maximum_states", 16},
                                                 {"maximum_steps", 512}};
  InstructionDecoder decoder;
  collect_direct_edges(image, decoder);
  auto sites = survey_dispatch(image, decoder, settings);
  auto transitions = classify_transitions(image, decoder, settings, sites);
  ObservationSet none;
  auto flows = resolve_targets(image, settings, sites, transitions, none);
  expand_state_space(image, decoder, settings, sites, flows, none);
  auto plan = plan_rewrites(image, decoder, settings, sites, flows, none);
  enrich_table_graph(image, settings, sites, plan);
  RewriteTransaction::prepare(image, plan);
  RewriteTransaction::prepare(image, plan_cleanup(image, decoder, settings));
}
} // namespace
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  using namespace a64dispatch;
  if (size > 65536)
    return 0;
  if (size && (data[0] == '{' || data[0] == '[')) {
    try {
      const auto document = parse_document({data, size});
      try {
        CodeImage::from_flat({data, size}, document);
      } catch (const std::exception &) {
      }
      try {
        exercise(CodeImage::from_snapshot(document));
      } catch (const std::exception &) {
      }
      try {
        site_from_json(document);
      } catch (const std::exception &) {
      }
      try {
        transition_from_json(document);
      } catch (const std::exception &) {
      }
      try {
        flow_from_json(document);
      } catch (const std::exception &) {
      }
      try {
        plan_from_json(document);
      } catch (const std::exception &) {
      }
    } catch (const std::exception &) {
    }
  }
  try {
    exercise(CodeImage::from_elf({data, size}));
  } catch (const std::exception &) {
  }
  if (size < 4)
    return 0;
  try {
    CodeImage image;
    MemoryRegion region;
    region.begin = 0x100000;
    region.bytes.assign(data, data + size - size % 4);
    region.executable = true;
    image.regions.push_back(region);
    image.functions.push_back({region.begin, region.end(), "fuzz"});
    InstructionDecoder decoder;
    for (Address address = region.begin; address < region.end(); address += 4)
      decoder.decode(address, *image.instruction(address));
    ConstantTracker tracker(image, decoder, 16, 4);
    tracker.resolve(region.end(), data[0] % 32, 32);
    tracker.resolve(region.end(), data[1] % 32, 64);
    exercise(std::move(image));
  } catch (const std::exception &) {
  }
  return 0;
}
