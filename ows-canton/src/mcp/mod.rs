//! MCP (Model Context Protocol) server module for AI agent integration.
//!
//! Exposes Canton wallet operations as MCP tools that can be used by AI agents
//! (Claude, GPT, LangChain) for wallet creation, command submission, contract
//! queries, and party management.
//! See `specs/08-mcp-tools.md` for the full specification.

pub mod tools;
