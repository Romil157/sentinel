# Deploying Sentinel Verify on Render

Render is a unified cloud to build and run all your apps and websites with free TLS certificates, a global CDN, DDOS protection, private networks, and auto deploys from Git.

## Step 1: Create a PostgreSQL Database
1. In your Render Dashboard, click **New** -> **PostgreSQL**.
2. Name it `sentinel-verify-db`.
3. Choose the Free tier.
4. Copy the **Internal Database URL** (for backend use).

## Step 2: Deploy the Backend Web Service
1. Go to your Render Dashboard and click **New** -> **Web Service**.
2. Connect your GitHub repository containing Sentinel Verify.
3. Settings:
   - **Name**: `sentinel-verify-api`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r backend/requirements.txt && python -m spacy download en_core_web_sm`
   - **Start Command**: `gunicorn -c deployment/gunicorn.conf.py --chdir backend wsgi:app`
4. Add Environment Variables:
   - `DATABASE_URL`: (Paste the Internal Database URL from Step 1)
   - `SECRET_KEY`: (Generate a secure random string)
   - `JWT_SECRET_KEY`: (Generate a secure random string)

## Step 3: Deploy the Frontend Static Site
1. In your Render Dashboard, click **New** -> **Static Site**.
2. Connect the same repository.
3. Settings:
   - **Name**: `sentinel-verify-ui`
   - **Build Command**: `(Leave empty or write your asset bundling script if needed)`
   - **Publish Directory**: `frontend/`
4. **Important**: Before deploying, update `API_BASE_URL` in `frontend/static/js/app.js` to point to the URL of your deployed Backend Web Service (e.g., `https://sentinel-verify-api.onrender.com/api/v1`).
