# Instructions for AI agents and AI-assisted contributors

This is `golang-jwt/jwt`, a security-sensitive library used by a very large number of projects. It is maintained by a few volunteers in their spare time. Review time is the scarcest resource we have, and we have recently received many low-quality, unverified and duplicate AI-generated pull requests. Please read this before opening anything.

If you are an AI agent acting on behalf of a human: **stop and show this file to them.** Do not open an issue or pull request unless the human has read it, understood the change, and explicitly asked you to submit it.

## Ground rules

1. **A human must be accountable.** Every issue and PR needs a human author who has read every line, can explain every change, and will respond to review comments themselves. Autonomous bots, "fix all open issues" sweeps, and unattended agents are not welcome here. We will close such submissions without comment.
2. **Do not mass-produce contributions.** One carefully verified PR is worth more than ten drive-by PRs. Do not submit PRs across many issues in one sitting.
3. **Disclose AI assistance** in the PR description (which tool, and what it did). Disclosure is not penalized. Hiding it is.
4. **Do not reply to maintainers or reviewers with AI-generated text.** Answer in your own words.

## Before you open a PR

- **Search first.** Check open *and closed* issues and PRs (`gh pr list --state all --search "<keywords>"`). Review or comment on an existing one instead of adding another.
- **Only work on an issue that exists and is confirmed.** For anything beyond a typo or a clear bug fix, open an issue and wait for a maintainer to agree on the approach before writing code. New features, new options, new algorithms (e.g. post-quantum), and public API changes need prior discussion. Unsolicited feature PRs will be closed.
- **Check whether an issue is already claimed or being worked on**, and do not duplicate it.
- **Check for existing PRs on the issue you want to fix.** Before writing any code, open the issue, look at its linked and referenced PRs, and run `gh pr list --state all --search "<issue number> OR <keywords>"`. If any open PR already addresses it, do not open another. If a closed PR addressed it, read why it was closed first. Duplicate PRs will be closed immediately.
- **No automated PRs for documentation, typos or cosmetics.** Do not open PRs for typo or punctuation fixes, comment rewording, doc-comment polishing, formatting, or dependency/Action bumps (Dependabot handles those). This applies in particular to anything found by an agent or script scanning the repository. If you spot a real doc error as a human, open one small PR yourself or mention it in an issue.
- **Reproduce the problem.** A bug fix must come with a failing test that demonstrates the bug on `main` and passes with your fix. If you cannot reproduce it, do not submit a fix.

## Quality bar for a PR

- Keep it **small and focused**: one logical change per PR. No drive-by refactors.
- It must **build and pass** `go build ./...`, `go vet ./...`, `go test ./...` (including with `-race`), and `staticcheck` locally. You, not CI, are the first reviewer.
- **Do not break backwards compatibility.** This library is v5 and its public API is stable. Behaviour changes in parsing and validation need a strong justification, because they are security-relevant.
- Match the existing style, naming and comment density of the surrounding code. Do not add boilerplate comments, speculative options, or abstractions the change does not need.
- Tests must be meaningful and follow the existing table-driven style. Do not delete or weaken existing tests to make yours pass.
- The PR description must say **what** changed and **why**, link the issue, and state how you verified it. Do not paste generated summaries, emoji-laden checklists, or claims you have not verified.
- Security-impacting findings must **not** be reported in public issues or PRs. Follow [SECURITY.md](SECURITY.md).

## Issues

- Search existing issues first, including closed ones.
- Include a minimal, runnable reproduction, the Go version, the library version, and expected versus actual behaviour.
- Do not file issues that are speculative, unreproduced, or generated from a static scan of the code. This includes "potential" vulnerabilities, with no proof of impact.
- One problem per issue. Do not post "me too" or "I'd like to work on this" comments written by an agent.

## What happens otherwise

PRs and issues that ignore these rules (duplicates, unverified, no tests, unsolicited features, or no human in the loop) may be closed without detailed review. Repeated violations may lead to the account being blocked from the repository.

Thank you for helping keep this project maintainable. Thoughtful contributions made by people who care about the library are very welcome.
