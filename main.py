from agent.agent import Agent


def main():

    print("=" * 60)
    print("                 AGENTGUARD AI AGENT")
    print("=" * 60)

    print(
        "AgentGuard security monitoring is enabled."
    )

    print(
        "Type 'exit' to quit.\n"
    )

    agent = Agent()

    while True:

        user_input = input("You: ")

        if user_input.lower().strip() == "exit":

            print(
                "Goodbye!"
            )

            break

        if not user_input.strip():

            continue

        print(
            "\nAgent:"
        )

        answer = agent.run(
            user_input
        )

        print(
            "\nFinal Answer:"
        )

        print(
            answer
        )

        print(
            "\n" + "-" * 60
        )


if __name__ == "__main__":

    main()