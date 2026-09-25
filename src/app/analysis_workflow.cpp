#include <a64dispatch/workflow.hpp>
#include <algorithm>
#include <set>
namespace a64dispatch {
namespace {
std::string document_hash(const Json &document) {
  // Object ordering in configuration files is not significant.
  const auto encoded = nlohmann::json(document).dump();
  return sha256(
      {reinterpret_cast<const std::uint8_t *>(encoded.data()), encoded.size()});
}
unsigned stage_depth(const std::string &stage) {
  if (stage == "survey")
    return 1;
  if (stage == "classify")
    return 2;
  if (stage == "resolve")
    return 3;
  if (stage == "plan")
    return 4;
  throw AnalysisError("unknown analysis stage: " + stage);
}
void validate_observations(const CodeImage &image,
                           const ObservationSet &observations,
                           unsigned maximum_targets) {
  for (const auto &[site, targets] : observations.targets) {
    if (targets.size() > maximum_targets)
      throw AnalysisError("observed target count exceeds maximum_targets");
    auto instruction = image.instruction(site);
    if (!instruction || (*instruction & 0xfffffc1f) != 0xd61f0000)
      throw AnalysisError("trace site is not a mapped BR instruction");
    for (auto target : targets)
      if (!image.valid_target(target))
        throw AnalysisError("trace target is not aligned executable memory");
  }
}
} // namespace
AnalysisWorkflow::AnalysisWorkflow(CodeImage input, Json configuration)
    : input_(std::move(input)), analysis_image_(input_),
      configuration_(std::move(configuration)),
      settings_(AnalysisSettings::from_json(configuration_, input_)) {
  input_.validate();
  mode_ = configuration_.value("mode", std::string("graph"));
  if (mode_ != "graph" && mode_ != "linear" && mode_ != "full")
    throw AnalysisError("mode must be graph, linear or full");
  collect_direct_edges(analysis_image_, decoder_);
  if (configuration_.contains("functions")) {
    const auto &selectors = configuration_.at("functions");
    if (!selectors.is_array() || selectors.empty() || selectors.size() > 10000)
      throw AnalysisError(
          "functions must select 1..10000 function entries or names");
    std::vector<std::pair<Address, Address>> ranges;
    for (const auto &selector : selectors) {
      const FunctionSpan *function = nullptr;
      for (const auto &entry : input_.functions)
        if (selector.is_string() &&
            entry.label == selector.get<std::string>()) {
          if (function)
            throw AnalysisError("ambiguous function name");
          function = &entry;
        }
      if (!function) {
        auto address = parse_address(selector);
        function = input_.function_at(address);
        if (!function || function->begin != address)
          throw AnalysisError(
              "function selector must identify a function entry");
      }
      bool selected = false;
      for (const auto &[begin, end] : settings_.ranges) {
        const auto first = std::max(begin, function->begin),
                   last = std::min(end, function->end);
        if (first < last) {
          ranges.emplace_back(first, last);
          selected = true;
        }
      }
      if (!selected)
        throw AnalysisError(
            "function lies outside selected executable regions");
    }
    settings_.ranges = std::move(ranges);
  }
  if (configuration_.contains("trace_command")) {
    observations_.merge(
        collect_external_trace(input_, configuration_.at("trace_command")));
    if (configuration_.contains("observations"))
      observations_.merge(configuration_.at("observations"));
    configuration_["observations"] = observations_.json();
    configuration_.erase("trace_command");
  }
  configuration_hash_ = document_hash(configuration_);
  if (configuration_.contains("observations")) {
    observations_.merge(configuration_.at("observations"));
    validate_observations(input_, observations_, settings_.maximum_targets);
  }
}
Json AnalysisWorkflow::envelope(const std::string &name) const {
  return {{"schema_version", 1},
          {"producer", "A64Dispatch"},
          {"stage", name},
          {"source_sha256", input_.fingerprint()},
          {"configuration_sha256", configuration_hash_}};
}
Json AnalysisWorkflow::exercise() {
  if (exercised_)
    return executions_;
  const auto specification = configuration_.at("execution");
  const auto vectors = specification.value("known_vectors", Json::array());
  if (!vectors.is_array() || vectors.empty() || vectors.size() > 10000)
    throw AnalysisError("trace and emulation require 1..10000 known vectors");
  // Stage all observations locally. A failed vector must not leave a partially
  // trusted trace behind when this workflow object is reused by an embedding.
  auto accumulated = observations_;
  auto states = state_targets_;
  Json rows = Json::array();
  for (const auto &vector : vectors) {
    auto local = specification;
    if (vector.contains("input_spec"))
      local["input"] = vector["input_spec"];
    if (vector.contains("output_spec"))
      local["output"] = vector["output_spec"];
    auto entry =
        parse_address(vector.contains("entry") ? vector.at("entry")
                                               : specification.at("entry"));
    auto input = parse_hex(vector.at("input"));
    auto expected = parse_hex(vector.at("output"));
    auto result = ExecutionOracle(local).run(input_, entry, input, sites_);
    if (result.output != expected)
      throw AnalysisError("known vector does not match the original image at " +
                          hex_address(entry));
    accumulated.merge(result.observations.json());
    validate_observations(input_, accumulated, settings_.maximum_targets);
    for (const auto &[site, values] : result.state_targets)
      for (const auto &[state, targets] : values)
        states[site][state].insert(targets.begin(), targets.end());
    rows.push_back({{"entry", hex_address(entry)},
                    {"input", hex_bytes(input)},
                    {"expected", hex_bytes(expected)},
                    {"execution", execution_json(result)}});
  }
  observations_ = std::move(accumulated);
  state_targets_ = std::move(states);
  executions_ = std::move(rows);
  exercised_ = true;
  return executions_;
}
void AnalysisWorkflow::analyze(unsigned depth) {
  if (depth_ < 1 && depth >= 1) {
    sites_ = survey_dispatch(analysis_image_, decoder_, settings_);
    // A range may cover part of a function. Every proposed byte still has to
    // lie in that range; filtering solely by the function's entry is unsafe.
    depth_ = 1;
  }
  if (depth_ < 2 && depth >= 2) {
    transitions_ =
        classify_transitions(analysis_image_, decoder_, settings_, sites_);
    depth_ = 2;
  }
  if (depth_ < 3 && depth >= 3) {
    if (configuration_.value("analysis", Json::object())
            .value("emulate", false))
      exercise();
    flows_ = resolve_targets(analysis_image_, settings_, sites_, transitions_,
                             observations_);
    for (auto &flow : flows_) {
      auto at_site = state_targets_.find(flow.transition.branch);
      if (at_site == state_targets_.end())
        continue;
      for (auto &target : flow.targets) {
        auto found = at_site->second.find(target.state);
        if (found == at_site->second.end() || found->second.empty())
          continue;
        if (found->second.size() != 1 ||
            (target.destination &&
             !found->second.contains(*target.destination))) {
          target.evidence = "conflict";
          target.reason = "execution disagrees with the state-specific static "
                          "target or observed multiple targets";
          continue;
        }
        const auto destination = *found->second.begin();
        if (!input_.valid_target(destination)) {
          target.evidence = "invalid";
          target.reason = "emulated target is not aligned executable memory";
        } else if (!target.destination) {
          target.destination = destination;
          target.evidence = "emulated";
          target.reason =
              "state-specific execution evidence; not a proof over all inputs";
        }
      }
    }
    expansion_ =
        expand_state_space(analysis_image_, decoder_, settings_, sites_, flows_,
                           observations_, state_targets_);
    depth_ = 3;
  }
  if (depth_ < 4 && depth >= 4) {
    plan_ = plan_rewrites(analysis_image_, decoder_, settings_, sites_, flows_,
                          observations_);
    plan_.source_sha256 = input_.fingerprint();
    std::set<std::pair<Address, Address>> graph;
    for (const auto &edge : plan_.graph)
      graph.emplace(edge.source, edge.target);
    for (const auto &site : sites_) {
      const auto found = observations_.targets.find(site.branch);
      if (found != observations_.targets.end())
        for (auto target : found->second)
          if (graph.emplace(site.branch, target).second)
            plan_.graph.push_back({site.branch, target, false});
    }
    std::set<Address> rejected;
    for (const auto &edit : plan_.edits)
      if (!settings_.selects(edit.address))
        rejected.insert(edit.site);
    std::erase_if(plan_.edits, [&](const auto &edit) {
      return rejected.contains(edit.site);
    });
    for (auto site : rejected)
      plan_.skipped.push_back(
          {{"site", hex_address(site)},
           {"reason",
            "one or more grouped edits lie outside the selected ranges"}});
    table_graph_ =
        enrich_table_graph(analysis_image_, settings_, sites_, plan_);
    depth_ = 4;
  }
}
Json AnalysisWorkflow::stage(const std::string &name) {
  const auto depth = stage_depth(name);
  analyze(depth);
  auto result = envelope(name);
  result["sites"] = Json::array();
  for (const auto &site : sites_)
    result["sites"].push_back(site_json(site));
  if (depth >= 2) {
    result["transitions"] = Json::array();
    for (const auto &transition : transitions_)
      result["transitions"].push_back(transition_json(transition));
  }
  if (depth >= 3) {
    result["flows"] = Json::array();
    for (const auto &flow : flows_)
      result["flows"].push_back(flow_json(flow));
    result["observations"] = observations_.json();
    result["executions"] = executions_;
    result["state_expansion"] = expansion_;
  }
  if (depth >= 4) {
    result["plan"] = plan_.json();
    result["table_graph"] = table_graph_;
  }
  return result;
}
void AnalysisWorkflow::check_artifact(const Json &artifact) {
  if (artifact.at("schema_version") != 1 ||
      artifact.at("producer") != "A64Dispatch" ||
      artifact.at("source_sha256").get<std::string>() != input_.fingerprint() ||
      artifact.at("configuration_sha256").get<std::string>() !=
          configuration_hash_)
    throw AnalysisError(
        "artifact version, source or configuration does not match");
  const auto name = artifact.at("stage").get<std::string>();
  auto expected = stage(name);
  if (nlohmann::json(expected) != nlohmann::json(artifact))
    throw AnalysisError(
        "stage artifact differs from freshly regenerated analysis");
}
RewritePlan AnalysisWorkflow::effective_plan(const std::string &command) const {
  if (command == "cleanup") {
    auto proposal = plan_cleanup(analysis_image_, decoder_, settings_);
    proposal.source_sha256 = input_.fingerprint();
    return proposal;
  }
  auto result = plan_;
  if (command == "graph" || mode_ == "graph")
    result.edits.clear();
  return result;
}
CodeImage AnalysisWorkflow::with_graph(CodeImage candidate,
                                       const RewritePlan &plan,
                                       Json &added) const {
  std::set<std::pair<Address, Address>> known;
  for (const auto &edge : candidate.references)
    known.emplace(edge.source, edge.target);
  added = Json::array();
  for (const auto &edge : plan.graph)
    if (known.emplace(edge.source, edge.target).second) {
      candidate.references.push_back({edge.source, edge.target, true});
      added.push_back({{"source", hex_address(edge.source)},
                       {"target", hex_address(edge.target)}});
    }
  return candidate;
}
Json AnalysisWorkflow::receipt(const std::string &command,
                               const RewritePlan &plan,
                               const CodeImage &candidate, const Json &added,
                               bool applied, const Json &verification) const {
  auto result = envelope(command);
  result["mode"] = mode_;
  result["applied"] = applied;
  result["plan"] = plan.json();
  result["verification"] = verification;
  result["table_graph"] = table_graph_;
  result["state_expansion"] = expansion_;
  result["candidate_sha256"] = candidate.fingerprint();
  result["added_edges"] = applied ? added : Json::array();
  result["proposed_edges"] = added;
  result["image"] = candidate.snapshot();
  return result;
}
Json AnalysisWorkflow::execute(const std::string &command, bool apply,
                               const CodeImage *candidate) {
  if (command == "batch")
    return execute_batch(apply);
  if (command == "survey" || command == "classify" || command == "resolve" ||
      command == "plan") {
    if (apply)
      throw AnalysisError("analysis stages are read-only");
    return stage(command);
  }
  if (command == "trace") {
    if (apply)
      throw AnalysisError("trace is read-only");
    analyze(1);
    auto result = envelope("trace");
    result["executions"] = exercise();
    result["observations"] = observations_.json();
    // Trace may have changed evidence after a caller requested another stage.
    depth_ = std::min(depth_, 2u);
    return result;
  }
  if (command == "discover") {
    if (apply)
      throw AnalysisError("discover is read-only");
    analyze(4);
    auto result = envelope(command);
    result["jobs"] = Json::array();
    for (const auto &function : input_.functions) {
      Json sites = Json::array();
      for (const auto &site : sites_)
        if (site.parent == function.begin)
          sites.push_back(hex_address(site.branch));
      if (sites.empty())
        continue;
      std::size_t edits = 0, skipped = 0;
      for (const auto &edit : plan_.edits)
        edits += edit.parent == function.begin;
      for (const auto &skip : plan_.skipped)
        if (skip.contains("site")) {
          auto parent = input_.function_at(parse_address(skip.at("site")));
          skipped += parent && parent->begin == function.begin;
        }
      result["jobs"].push_back({{"function", hex_address(function.begin)},
                                {"name", function.label},
                                {"sites", sites},
                                {"proposed_instructions", edits},
                                {"skipped", skipped}});
    }
    return result;
  }
  if (command != "preview" && command != "run" && command != "graph" &&
      command != "verify" && command != "regress" && command != "cleanup")
    throw AnalysisError("unknown workflow command: " + command);
  if (apply && command != "run" && command != "graph" && command != "cleanup")
    throw AnalysisError("--apply is only valid for run, graph and cleanup");
  if (apply && command == "cleanup" && mode_ == "graph")
    throw AnalysisError("cleanup application requires mode linear or full");
  analyze(4);
  auto plan = effective_plan(command);
  auto prepared = RewriteTransaction::prepare(input_, plan);
  auto expectations = check_plan_expectations(
      prepared, plan, configuration_.value("regression", Json::object()));
  if (apply && !expectations.at("passed").get<bool>())
    throw AnalysisError(
        "configured regression expectations failed; application refused");
  Json verification = {{"status", "not_run"}, {"passed", false}};
  if (command == "verify" || command == "regress" ||
      (apply && !plan.edits.empty())) {
    ExecutionOracle oracle(configuration_.at("execution"));
    if (command == "verify" && candidate) {
      // A supplied snapshot must be the regenerated byte candidate, optionally
      // with exactly the graph metadata that this workflow owns. Per-edit
      // checks and finite outputs cannot identify changes elsewhere in an
      // image.
      Json added;
      const auto graphed = with_graph(prepared, plan, added);
      const auto supplied_hash = candidate->fingerprint();
      const bool matches = supplied_hash == prepared.fingerprint() ||
                           supplied_hash == graphed.fingerprint();
      if (!matches) {
        verification = {{"status", "not_run"},
                        {"passed", false},
                        {"error", "supplied candidate differs from the "
                                  "regenerated bytes or owned graph"}};
      } else {
        // Reuse every application gate, including original instruction/target
        // coverage and all candidate branch outcomes. The matching fingerprints
        // above bind the supplied bytes to the image exercised by this gate.
        auto checked = input_;
        try {
          verification =
              RewriteTransaction::commit(checked, input_, plan, oracle);
          verification["status"] = "passed";
        } catch (const AnalysisError &error) {
          verification = {
              {"status", "failed"}, {"passed", false}, {"error", error.what()}};
        }
      }
      auto result = envelope(command);
      result["candidate_match"] = matches;
      result["supplied_sha256"] = supplied_hash;
      result["verification"] = verification;
      result["self_check"] = RewriteTransaction::self_check(*candidate, plan);
      result["expectations"] = check_plan_expectations(
          *candidate, plan, configuration_.value("regression", Json::object()));
      result["passed"] = result.at("expectations").at("passed").get<bool>() &&
                         verification.at("passed").get<bool>() &&
                         result["self_check"].at("passed").get<bool>();
      return result;
    }
    // The same coverage and target-set requirements guard CLI and library
    // writes.
    auto current = input_;
    verification = RewriteTransaction::commit(current, input_, plan, oracle);
    verification["status"] = "passed";
    prepared = std::move(current);
  }
  if (command == "regress") {
    auto restored = prepared;
    RewriteTransaction::restore(restored, input_, plan);
    AnalysisWorkflow rerun(restored, configuration_);
    const auto repeated = rerun.stage("plan");
    const bool same_plan =
        nlohmann::json(repeated.at("plan")) == nlohmann::json(plan_.json());
    auto restored_vectors = ExecutionOracle(configuration_.at("execution"))
                                .compare(input_, restored, sites_);
    auto result = envelope(command);
    result["verification"] = verification;
    result["restored_verification"] = restored_vectors;
    result["restored_sha256"] = restored.fingerprint();
    result["identical_plan_and_skips"] = same_plan;
    result["expectations"] = expectations;
    result["passed"] = expectations.at("passed").get<bool>() && same_plan &&
                       restored.fingerprint() == input_.fingerprint() &&
                       restored_vectors.at("passed").get<bool>();
    return result;
  }
  Json added;
  auto prospective = with_graph(std::move(prepared), plan, added);
  auto result = receipt(command, plan, prospective, added, apply, verification);
  result["expectations"] = expectations;
  if (command == "verify")
    result["passed"] = verification.at("passed").get<bool>() &&
                       expectations.at("passed").get<bool>();
  return result;
}
Json AnalysisWorkflow::restore(const Json &record, const CodeImage *current) {
  if (record.at("schema_version") != 1 ||
      record.at("producer") != "A64Dispatch" ||
      !record.at("applied").get<bool>() ||
      record.at("source_sha256").get<std::string>() != input_.fingerprint() ||
      record.at("configuration_sha256").get<std::string>() !=
          configuration_hash_)
    throw AnalysisError("restore requires a matching applied receipt");
  const auto command = record.at("stage").get<std::string>();
  if (command != "run" && command != "graph" && command != "cleanup")
    throw AnalysisError("receipt is not from an applying command");
  analyze(4);
  auto plan = effective_plan(command);
  if (nlohmann::json(record.at("plan")) != nlohmann::json(plan.json()))
    throw AnalysisError("receipt plan differs from current source analysis");
  Json added;
  auto expected =
      with_graph(RewriteTransaction::prepare(input_, plan), plan, added);
  const auto recorded = CodeImage::from_snapshot(record.at("image"));
  if (record.at("candidate_sha256").get<std::string>() !=
          expected.fingerprint() ||
      recorded.fingerprint() != expected.fingerprint() ||
      record.at("added_edges") != added)
    throw AnalysisError("receipt image or graph ownership does not match");
  if (current && current->fingerprint() != expected.fingerprint() &&
      current->fingerprint() != input_.fingerprint())
    throw AnalysisError("current image has unrelated changes; restore refused");
  auto result = envelope("restore");
  result["restored"] = true;
  result["removed_edges"] = added;
  result["image"] = input_.snapshot();
  result["restored_sha256"] = input_.fingerprint();
  return result;
}
} // namespace a64dispatch
