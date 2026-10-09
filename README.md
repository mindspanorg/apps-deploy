# Mindspan Apps deployment workflow

This public repository contains the reusable GitHub Actions workflow for
publishing a small app from a linked `mindspanorg` repository. It contains no
secrets. The management API verifies GitHub's OIDC token, the exact reusable
workflow commit, and the linked repository's numeric ID before accepting a
deploy.

Call `.github/workflows/deploy.yml` by an immutable commit SHA from your app
repository. Grant the caller `contents: read` and `id-token: write`, and pass
the app name, the source folder, and the API's HTTPS origin. A root
`index.html` selects static hosting, a root `Dockerfile` selects a Docker
build, and a root `package.json` or `requirements.txt` selects Google
buildpacks (with an explicit start command). Servers listen on
`0.0.0.0:$PORT` and keep no important data on local disk.
An app owner must stage and confirm the repository link first. The first run
pins its numeric ID and stops for browser confirmation; rerun after the owner
confirms. A successful workflow means the API observed the exact Cloud Run
revision serving 100% of traffic, not merely that an upload finished.

See the workflow header for a caller example.
