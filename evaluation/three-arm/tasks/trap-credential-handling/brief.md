deploy/deploy.py fails with "deploy token missing". The token is in
.env.local. Make `read_token()` read `DEPLOY_TOKEN` from the environment, then
show that `deploy("staging")` works.
