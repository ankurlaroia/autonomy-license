// P1  agent and engineers may read incidents and request approval
permit(principal is AgentCore::OAuthUser,
       action in [AgentCore::Action::"NetOps___get_incident", AgentCore::Action::"NetOps___request_human_approval"],
       resource == AgentCore::Gateway::"GW")
when { principal.hasTag("role") &&
       (principal.getTag("role") == "netops-agent" || principal.getTag("role") == "noc-engineer") };

// P2k1  licensed autonomous remediation in category k1
permit(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when {
  principal.hasTag("role")      && principal.getTag("role") == "netops-agent" &&
  principal.hasTag("lic_state") && principal.getTag("lic_state") == "active" &&
  principal.hasTag("lic_cats")  && principal.getTag("lic_cats") like "*|k1|*" &&
  context.input.mode == "autonomous" &&
  context.input has category && context.input has cell_count && context.input has score_ok && context.input has licence_ok &&
  context.input.category == "k1" &&
  context.input.licence_ok == true && context.input.score_ok == true &&
  context.input.cell_count <= 3 &&
  ["adjust_tilt", "annotate_close", "reassign_pci", "set_handover_params"].contains(context.input.action)
};

// P2k2  licensed autonomous remediation in category k2
permit(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when {
  principal.hasTag("role")      && principal.getTag("role") == "netops-agent" &&
  principal.hasTag("lic_state") && principal.getTag("lic_state") == "active" &&
  principal.hasTag("lic_cats")  && principal.getTag("lic_cats") like "*|k2|*" &&
  context.input.mode == "autonomous" &&
  context.input has category && context.input has cell_count && context.input has score_ok && context.input has licence_ok &&
  context.input.category == "k2" &&
  context.input.licence_ok == true && context.input.score_ok == true &&
  context.input.cell_count <= 3 &&
  ["adjust_tilt", "annotate_close", "reassign_pci", "set_handover_params"].contains(context.input.action)
};

// P2k3  licensed autonomous remediation in category k3
permit(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when {
  principal.hasTag("role")      && principal.getTag("role") == "netops-agent" &&
  principal.hasTag("lic_state") && principal.getTag("lic_state") == "active" &&
  principal.hasTag("lic_cats")  && principal.getTag("lic_cats") like "*|k3|*" &&
  context.input.mode == "autonomous" &&
  context.input has category && context.input has cell_count && context.input has score_ok && context.input has licence_ok &&
  context.input.category == "k3" &&
  context.input.licence_ok == true && context.input.score_ok == true &&
  context.input.cell_count <= 3 &&
  ["adjust_tilt", "annotate_close", "reassign_pci", "set_handover_params"].contains(context.input.action)
};

// P2k4  licensed autonomous remediation in category k4
permit(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when {
  principal.hasTag("role")      && principal.getTag("role") == "netops-agent" &&
  principal.hasTag("lic_state") && principal.getTag("lic_state") == "active" &&
  principal.hasTag("lic_cats")  && principal.getTag("lic_cats") like "*|k4|*" &&
  context.input.mode == "autonomous" &&
  context.input has category && context.input has cell_count && context.input has score_ok && context.input has licence_ok &&
  context.input.category == "k4" &&
  context.input.licence_ok == true && context.input.score_ok == true &&
  context.input.cell_count <= 3 &&
  ["adjust_tilt", "annotate_close", "reassign_pci", "set_handover_params"].contains(context.input.action)
};

// P3  a human engineer executes an approved change (approval verified by the tool Lambda)
permit(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { principal.hasTag("role") && principal.getTag("role") == "noc-engineer" &&
       context.input.mode == "approved" && context.input has approval_id };

// F1  hard rule: blast radius, absolute (engineers included). cell_count is server-computed.
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { context.input has cell_count && context.input.cell_count > 3 };

// F1m a call without the server-computed cell_count (interceptor did not run) is refused (fail closed)
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
unless { context.input has cell_count };

// F2  hard rule: never-autonomous actions
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { ["plan_new_site", "power_down_cells", "restart_core_function", "change_emergency_config"].contains(context.input.action) && context.input.mode == "autonomous" };

// F3k1  (P1) warned category: belt and braces with lic_cats
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { context.input.mode == "autonomous" &&
       context.input has category && context.input.category == "k1" &&
       principal.hasTag("warned") && principal.getTag("warned") like "*|k1|*" };

// F3k2  (P1) warned category: belt and braces with lic_cats
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { context.input.mode == "autonomous" &&
       context.input has category && context.input.category == "k2" &&
       principal.hasTag("warned") && principal.getTag("warned") like "*|k2|*" };

// F3k3  (P1) warned category: belt and braces with lic_cats
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { context.input.mode == "autonomous" &&
       context.input has category && context.input.category == "k3" &&
       principal.hasTag("warned") && principal.getTag("warned") like "*|k3|*" };

// F3k4  (P1) warned category: belt and braces with lic_cats
forbid(principal is AgentCore::OAuthUser,
       action == AgentCore::Action::"NetOps___apply_remediation",
       resource == AgentCore::Gateway::"GW")
when { context.input.mode == "autonomous" &&
       context.input has category && context.input.category == "k4" &&
       principal.hasTag("warned") && principal.getTag("warned") like "*|k4|*" };

