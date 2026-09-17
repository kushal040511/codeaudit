# Page-capture sandbox image: Playwright's Chromium plus the Python client.
# The upstream image ships the browsers (/ms-playwright) but not the Python package,
# which must match the browser build exactly.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0

RUN pip3 install --no-cache-dir --break-system-packages "playwright==1.63.0" \
    && python3 -c "import playwright.sync_api"

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
