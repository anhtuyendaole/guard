# Gateweave Guard

Security in one place for teams on Cloudflare. Guard reads your account's Security Insights, your
zones' WAF and bot activity, and the lockfiles of your repositories, and shows what is wrong in one
list. A finding becomes a Gateweave Track issue, or a fix pull request from Gateweave Agents.

Guard only reads. It never changes a Cloudflare setting or a repository by itself.

Your AI assistant can ask it what is wrong: paste `https://<your-guard>/mcp` into Claude Code or any
MCP client and sign in. See [docs/self-hosting.md](docs/self-hosting.md).

This repository is private until the first release. The plan is on the Gateweave board (GRD-1).

Licensed under the GNU Affero General Public License v3.0 only.
