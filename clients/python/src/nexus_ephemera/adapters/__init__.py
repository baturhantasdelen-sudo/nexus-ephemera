"""Pilot adapters. They do not hand a provider token to the agent."""

from .github import GithubIssuePolicy, ReferenceGithubIssueTransport, IssueReceipt

__all__ = ["GithubIssuePolicy", "ReferenceGithubIssueTransport", "IssueReceipt"]
