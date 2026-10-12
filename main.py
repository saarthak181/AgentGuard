from __future__ import annotations

import argparse

from agent import Agent, AgentError


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentGuard local document assistant")
    parser.add_argument("task", nargs="?", help="Task for the local agent")
    parser.add_argument("--model", default="llama3.2:3b")
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    task = args.task or input("Task: ")
    try:
        result = Agent(args.model, args.max_steps, args.timeout).run(task)
    except AgentError as exc:
        parser.exit(1, f"AgentGuard: {exc}\n")
    print(result.answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
