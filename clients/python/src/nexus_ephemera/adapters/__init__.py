"""Pilot adapters. They do not hand a provider token to the agent."""

from .github import GithubIssuePolicy, GithubIssueTransport, IssueReceipt

__all__ = ["GithubIssuePolicy", "GithubIssueTransport", "IssueReceipt"]
