# Mintlify deployment

This directory is the Mintlify site root. `docs.json` and the MDX pages live together here.

## Local preview

1. Run `devvault doctor` before installing the CLI or creating large caches, and follow its live routing guidance.
2. From this directory, run `npx mint@latest dev` if the CLI is not already installed.
3. Check the desktop and mobile views, navigation, links, and image loading.

## Publish

1. Connect `RockxyApp/Tracexy` in the Mintlify dashboard, with **docs** as the documentation root and `main` as the production branch after the reviewed merge.
2. Confirm the Mintlify GitHub App can access the repository and that its deployment completes.
3. Verify the generated `*.mintlify.app` URL, navigation, search, images, and a public page from an unauthenticated browser.
4. Configure a custom domain later in Mintlify and the relevant DNS provider. The requested future hostname is `docs.tracexy.io`; `tracexy.com` is a different domain and does not itself control `tracexy.io` DNS. Confirm ownership and the final hostname before changing DNS.

Do not claim that a Git push alone proves deployment. The custom domain is not configured by this repository.
