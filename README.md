# The Paidwen action verifies each pull request in your own runner

Paidwen runs each pull request in a disposable environment, replays your user journeys in a real browser and blocks the merge when one breaks. The Paidwen GitHub App starts the Paidwen workflow of your repository, and this action runs the verification in your own GitHub Actions runner.

The setup guide is at https://paidwen.com/docs/install.

## Setup takes two files

1. Copy [templates/paidwen.yml](templates/paidwen.yml) to `.github/workflows/paidwen.yml` on your default branch. The file is the same for every repository.
2. Add `paidwen.yml` at the root of your repository to describe how your app starts and which journeys to replay. The reference is at https://paidwen.com/docs/paidwen-yml.

Put the test secrets in the GitHub environment named `paidwen`: `PAIDWEN_TEST_LOGIN`, `PAIDWEN_TEST_PASSWORD`, `PAIDWEN_STRIPE_TEST_KEY`, `PAIDWEN_ENV` and `PAIDWEN_MODEL_KEY`. The workflow reads no other secret.

## Your code stays in your runner

- The job runs on a fresh runner of your repository. Your code never leaves GitHub.
- The engine sends back only the verdict: the status, five lines, the result of each journey, the timings, the number of changed files and the address of the video artifact. It never sends code, logs or media.
- The video stays an artifact of your workflow run for 90 days.
- Your app runs in containers on an internal network without internet.
- The job never fails because of Paidwen. When Paidwen cannot verify, the Paidwen check says so.

## The job asks for two permissions

- `contents: read` checks out the pull request. The checkout keeps no credentials.
- `id-token: write` proves to Paidwen which repository, run and workflow is asking. The token has the audience `paidwen` and is exchanged before any code of the pull request is built. The verification step cannot request another token.

The GitHub App has no Contents permission, and Paidwen never requests the diff of a pull request.

## A large app can run on a larger runner

- The job runs on `ubuntu-latest`. Set `runs-on` under `with:` in your workflow file to a larger runner, or to a JSON list of labels for a self-hosted runner.
- On a GitHub-hosted runner, the job frees disk space before the build when less than 40 GB is left.

## The engine is signed

The action holds only a small bootstrap, [bootstrap/exchange.mjs](bootstrap/exchange.mjs), with no dependency. The engine comes from Paidwen at each run, and the bootstrap runs it only when four checks pass:

1. The engine is not older than the oldest version pinned in the bootstrap.
2. Its SHA-256 matches the fingerprint Paidwen announced.
3. Its ed25519 signature is valid for the key pinned in [bootstrap/engine-public-key.pem](bootstrap/engine-public-key.pem). The signature binds the name, the version, the SHA-256 and the size of the package.
4. The extracted `package.json` carries the signed name and version.

The bootstrap also refuses an archive that holds a link or a path outside its folder, and it extracts exactly the bytes it verified. The private signing key never lives on a Paidwen server.
