from security.logger import log_action


class AgentGuard:
    """
    Security layer between the AI agent and its tools.
    """

    SENSITIVE_KEYWORDS = [
        "password",
        "credential",
        "secret",
        "token",
        "private_key",
        "private key",
        "confidential"
    ]

    EXTERNAL_TOOLS = [
        "api_request",
        "email"
    ]

    def inspect_action(self, tool, arguments):
        """
        Inspect an action and determine its risk level.
        """

        argument_text = str(arguments).lower()

        # High-risk actions
        for keyword in self.SENSITIVE_KEYWORDS:

            if keyword in argument_text:

                return (
                    "high",
                    f"Sensitive keyword detected: {keyword}"
                )

        # Medium-risk actions
        if tool in self.EXTERNAL_TOOLS:

            return (
                "medium",
                f"External tool requires review: {tool}"
            )

        # Normal action
        return (
            "low",
            "No immediate security concerns detected"
        )

    def _execute_tool(self, tool_function, tool, arguments):
        """
        Execute a tool while handling the current tool
        argument formats.

        This prevents errors such as:

        search_files() got an unexpected keyword argument 'query'
        """

        # -----------------------------------------------------
        # SEARCH FILES
        # -----------------------------------------------------
        # Some versions of search_files use a positional
        # argument rather than query=.
        #
        # Example:
        # search_files(search_term)
        #
        # So pass the value positionally.

        if tool == "search_files":

            query = arguments.get("query")

            if query is None:

                query = arguments.get("search_term")

            if query is None:

                query = arguments.get("filename")

            if query is None:

                raise ValueError(
                    "search_files requires a search query."
                )

            return tool_function(query)

        # -----------------------------------------------------
        # READ FILE
        # -----------------------------------------------------

        if tool == "read_file":

            filename = arguments.get("filename")

            if filename is None:

                raise ValueError(
                    "read_file requires a filename."
                )

            return tool_function(filename)

        # -----------------------------------------------------
        # CALCULATOR
        # -----------------------------------------------------

        if tool == "calculator":

            expression = arguments.get("expression")

            if expression is None:

                raise ValueError(
                    "calculator requires an expression."
                )

            return tool_function(expression)

        # -----------------------------------------------------
        # OTHER TOOLS
        # -----------------------------------------------------

        return tool_function(**arguments)

    def execute(
        self,
        agent_id,
        session_id,
        tool,
        arguments
    ):
        """
        Inspect and execute an agent tool action.

        Returns:

        True, result
            if the action is allowed and successful.

        False, reason
            if the action is blocked, requires review,
            or execution fails.
        """

        from agent.tools import TOOLS

        # -----------------------------------------------------
        # CHECK TOOL
        # -----------------------------------------------------

        if tool not in TOOLS:

            reason = f"Unknown tool: {tool}"

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                action=tool,
                arguments=arguments,
                result=reason,
                status="blocked",
                risk_level="high"
            )

            return False, reason

        # -----------------------------------------------------
        # SECURITY INSPECTION
        # -----------------------------------------------------

        risk_level, reason = self.inspect_action(
            tool,
            arguments
        )

        # -----------------------------------------------------
        # HIGH RISK
        # -----------------------------------------------------

        if risk_level == "high":

            result = f"Action blocked. {reason}"

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                action=tool,
                arguments=arguments,
                result=result,
                status="blocked",
                risk_level="high"
            )

            return False, result

        # -----------------------------------------------------
        # MEDIUM RISK
        # -----------------------------------------------------

        if risk_level == "medium":

            result = f"Action requires review. {reason}"

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                action=tool,
                arguments=arguments,
                result=result,
                status="review",
                risk_level="medium"
            )

            return False, result

        # -----------------------------------------------------
        # LOW RISK
        # -----------------------------------------------------

        try:

            tool_function = TOOLS[tool]

            result = self._execute_tool(
                tool_function,
                tool,
                arguments
            )

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                action=tool,
                arguments=arguments,
                result=result,
                status="success",
                risk_level="low"
            )

            return True, result

        except Exception as error:

            error_message = str(error)

            log_action(
                agent_id=agent_id,
                session_id=session_id,
                action=tool,
                arguments=arguments,
                result=error_message,
                status="error",
                risk_level="low"
            )

            return False, (
                f"Tool execution failed: "
                f"{error_message}"
            )
        