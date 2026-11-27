# Contributing

Thanks for your interest in improving the FNX Labs Container Image Catalog.
Bug reports, documentation improvements, accessibility enhancements, and tested
generator changes are welcome.

## Before you start

- Search existing issues and pull requests to avoid duplicates.
- For security vulnerabilities, follow `SECURITY.md` instead of opening a public issue.
- Never include credentials, tokens, private network addresses, or personal
  data in issues, pull requests, commit messages, or file contents.

## Proposing a change

1. Fork the repository and create a topic branch from `main`.
2. Keep changes focused and explain the motivation in the pull request.
3. Update `README.md` when behaviour or generated outputs change.
4. Keep the attribution “Daniel G. Cosenza from FNX Labs” intact wherever the
   maintainer is named.

## Checks

Every push and pull request runs automated checks. A pull request must have
all of them green before it can be merged into `main`:

- **Public content check** — no private infrastructure details and correct
  maintainer attribution;
- **Catalog generator build** — `python3 scripts/build-catalog.py --owner dgcosenza --out site`;
- **Gitleaks** — secret scanning across the full history.

You can run the content check locally with `.github/scripts/public-check.sh`.

## Tests

The catalog's automated checks are the unit test suite, the public content
check, the catalog generator build, and the publish completeness gate.
Continuous integration runs all of them on every push and pull request. You
can run them locally with:

    python3 -m unittest discover -s tests -v
    .github/scripts/public-check.sh
    python3 scripts/build-catalog.py --owner dgcosenza --out site
    python3 .github/scripts/verify-catalog.py site

As major new functionality is added to the catalog generator or site, checks
or tests for that functionality must be added to this automated suite. Pull
requests that change generator behaviour or generated output should include
the corresponding check or test updates.

## Commit and pull request style

- Use clear, present-tense commit subjects (for example `fix: improve contrast on filter chips`).
- Describe only the change in the pull request body.
- Do not force-push, and do not delete published releases or tags.

## License

By contributing you agree that your contribution is licensed under the MIT
License described in `LICENSE`.
