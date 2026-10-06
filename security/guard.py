from security.logger import log_action


class AgentGuard:

    def __init__(self):

        # ----------------------------------------------------
        # Sensitive keywords
        # ----------------------------------------------------

        self.sensitive_keywords = [
            "password",
            "credential",
            "secret",
            "token",
            "private_key",
            "confidential",
        ]

        # ----------------------------------------------------
        # Tools that communicate externally
        # ----------------------------------------------------

        self.external_tools = [
            "api_request",
            "email",
        ]

    # ========================================================
    # INSPECT ACTION
    # ========================================================

    def inspect_action(
        self,
        agent_id,
        session_id,
        tool_name,
        arguments,
    ):
        """
        Inspect a requested action before execution.
        """

        risk_level = "low"

        reasons = []

        argument_text = str(arguments).lower()

        # ----------------------------------------------------
        # Sensitive information check
        # ----------------------------------------------------

        for keyword in self.sensitive_keywords:

            if keyword in argument_text:

                risk_level = "high"

                reasons.append(
                    f"Sensitive keyword detected: {keyword}"
                )

        # ----------------------------------------------------
        # External communication check
        # ----------------------------------------------------

        if tool_name in self.external_tools:

            if risk_level != "high":
                risk_level = "medium"

            reasons.append(
                "External communication tool requested."
            )

        # ----------------------------------------------------
        # Decision
        # ----------------------------------------------------

        if risk_level == "high":

            decision = "block"

        elif risk_level == "medium":

            decision = "review"

        else:

            decision = "allow"

        return {
            "risk_level": risk_level,
            "decision": decision,
            "reasons": reasons,
        }

    # ========================================================
    # EXECUTE THROUGH AGENTGUARD
    # ========================================================

    def execute(
        self,
        tool_function,
        agent_id,
        session_id,
        tool_name,
        arguments,
    ):
        """
        AgentGuard execution pipeline:

        Inspect
            ↓
        Decide
            ↓
        Execute
            ↓
        Log
        """

        inspection = self.inspect_action(
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
        )

        # ----------------------------------------------------
        # BLOCK HIGH-RISK ACTION
        # ----------------------------------------------------

        if inspection["decision"] == "block":

            result = "ACTION BLOCKED BY AGENTGUARD"

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                status="blocked",
                risk_level=inspection["risk_level"],
            )

            return {
                "success": False,
                "blocked": True,
                "result": result,
                "risk_level": inspection["risk_level"],
                "decision": inspection["decision"],
                "reasons": inspection["reasons"],
            }

        # ----------------------------------------------------
        # EXECUTE TOOL
        # ----------------------------------------------------

        try:

            result = tool_function(**arguments)

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                status="success",
                risk_level=inspection["risk_level"],
            )

            return {
                "success": True,
                "blocked": False,
                "result": result,
                "risk_level": inspection["risk_level"],
                "decision": inspection["decision"],
                "reasons": inspection["reasons"],
            }

        # ----------------------------------------------------
        # TOOL ERROR
        # ----------------------------------------------------

        except Exception as error:

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
                result=str(error),
                status="error",
                risk_level=inspection["risk_level"],
            )

            return {
                "success": False,
                "blocked": False,
                "result": str(error),
                "risk_level": inspection["risk_level"],
                "decision": inspection["decision"],
                "reasons": inspection["reasons"],
            }