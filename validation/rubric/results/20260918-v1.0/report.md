# Rubric validation (rubric v1.0)

20 repositories scored; labels from `labels.csv` (pre-registered). Bootstrap: 5000 resamples, seed 20260918. p: one-sided permutation test.

## Spearman ρ, label vs score

| Dimension | n | ρ | 95% CI | p |
|---|---|---|---|---|
| security | 20 | **0.32** | -0.22 – 0.70 | 0.0826 |
| dependencies | 20 | **0.43** | -0.04 – 0.81 | 0.0326 |
| architecture | 20 | **-0.16** | -0.63 – 0.29 | 0.7493 |
| code_health | 13 | **0.34** | -0.34 – 0.79 | 0.1234 |
| overall | 20 | **0.66** | 0.30 – 0.86 | 0.0014 |

## Within groups (the stricter test)

| Group | security | dependencies | architecture | code_health | overall |
|---|---|---|---|---|---|
| vulnerable | n/a (n=6) | -0.21 (n=6) | -0.62 (n=6) | 0.50 (n=3) | n/a (n=6) |
| tutorial | -0.71 (n=5) | 0.00 (n=5) | -0.78 (n=5) | -0.26 (n=4) | -0.32 (n=5) |
| mature | -0.52 (n=9) | 0.00 (n=9) | -0.13 (n=9) | 0.83 (n=6) | 0.41 (n=9) |

## Median score per group

| Group | security | dependencies | architecture | code_health | overall |
|---|---|---|---|---|---|
| vulnerable | 18.7 | 0.1 | 96.4 | 95.2 | 40.5 |
| tutorial | 77.6 | 1.4 | 78.7 | 98.6 | 69.5 |
| mature | 69.6 | 34.9 | 95.0 | 96.7 | 74.1 |

## Scores

| Repository | Group | security | dependencies | architecture | code_health | overall | labels |
|---|---|---|---|---|---|---|---|
| psf/requests | mature | 65.9 | 100.0 | 95.0 | 92.6 | 83.9 | 5/5/4/4/5 |
| encode/starlette | mature | 71.7 | 75.8 | 100.0 | 96.1 | 83.0 | 5/5/5/5/5 |
| mjhea0/flaskr-tdd | tutorial | 77.6 | 42.3 | 82.6 | 99.7 | 76.0 | 3/3/2/3/3 |
| fastapi/full-stack-fastapi-template | mature | 94.0 | 2.0 | 88.5 | 98.2 | 75.3 | 4/5/5/5/5 |
| axios/axios | mature | 96.5 | 8.4 | 98.8 | n/a | 75.1 | 5/5/4/4/5 |
| encode/django-rest-framework | mature | 42.3 | 100.0 | 90.4 | 95.2 | 74.1 | 5/5/4/4/5 |
| encode/httpx | mature | 69.6 | 34.9 | 96.1 | 97.2 | 73.5 | 5/4/5/5/5 |
| gothinkster/django-realworld-example-app | tutorial | 80.4 | 7.1 | 96.1 | 90.4 | 70.9 | 3/1/3/3/2 |
| gothinkster/node-express-realworld-example-app | tutorial | 100.0 | 0.1 | 78.0 | n/a | 69.5 | 3/3/4/3/3 |
| expressjs/express | mature | 38.1 | 100.0 | 100.0 | n/a | 69.1 | 5/5/4/4/5 |
| anxolerd/dvpwa | vulnerable | 83.0 | 0.5 | 81.9 | 95.6 | 68.8 | 1/1/3/3/1 |
| gothinkster/flask-realworld-example-app | tutorial | 74.6 | 0.1 | 78.7 | 98.8 | 65.4 | 3/1/4/3/2 |
| appsecco/dvna | vulnerable | 19.8 | 100.0 | 97.3 | n/a | 59.2 | 1/1/2/2/1 |
| excalidraw/excalidraw | mature | 85.0 | 0.0 | 66.6 | n/a | 59.2 | 4/5/4/4/4 |
| pallets/flask | mature | 58.8 | 24.3 | 48.8 | 97.5 | 57.6 | 5/5/5/5/5 |
| we45/Vulnerable-Flask-App | vulnerable | 10.8 | 0.0 | 98.3 | 95.2 | 43.0 | 1/1/1/1/1 |
| miguelgrinberg/microblog | tutorial | 20.5 | 1.4 | 52.4 | 98.4 | 38.6 | 4/3/4/4/4 |
| snoopysecurity/dvws-node | vulnerable | 33.2 | 0.1 | 85.4 | n/a | 38.0 | 1/2/2/2/1 |
| adeyosemanputra/pygoat | vulnerable | 0.3 | 0.0 | 95.7 | 89.3 | 37.1 | 1/2/2/2/1 |
| OWASP/NodeGoat | vulnerable | 17.6 | 0.0 | 97.1 | n/a | 33.1 | 1/1/3/3/1 |

Labels column order: security, dependencies, architecture, code_health, overall.

## Inversions (labels differ by ≥ 2, scores disagree): 141

- **security**: encode/starlette (label 5, score 71.7) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: encode/httpx (label 5, score 69.6) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: pallets/flask (label 5, score 58.8) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: encode/django-rest-framework (label 5, score 42.3) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: expressjs/express (label 5, score 38.1) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: gothinkster/flask-realworld-example-app (label 3, score 74.6) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: miguelgrinberg/microblog (label 4, score 20.5) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: gothinkster/django-realworld-example-app (label 3, score 80.4) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: mjhea0/flaskr-tdd (label 3, score 77.6) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: psf/requests (label 5, score 65.9) < anxolerd/dvpwa (label 1, score 83.0)
- **security**: miguelgrinberg/microblog (label 4, score 20.5) < snoopysecurity/dvws-node (label 1, score 33.2)
- **security**: encode/starlette (label 5, score 71.7) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: encode/starlette (label 5, score 71.7) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: encode/starlette (label 5, score 71.7) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: encode/starlette (label 5, score 71.7) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **security**: encode/httpx (label 5, score 69.6) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: encode/httpx (label 5, score 69.6) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: encode/httpx (label 5, score 69.6) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: encode/httpx (label 5, score 69.6) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **security**: pallets/flask (label 5, score 58.8) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: pallets/flask (label 5, score 58.8) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: pallets/flask (label 5, score 58.8) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: pallets/flask (label 5, score 58.8) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **security**: encode/django-rest-framework (label 5, score 42.3) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: encode/django-rest-framework (label 5, score 42.3) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: encode/django-rest-framework (label 5, score 42.3) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: encode/django-rest-framework (label 5, score 42.3) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **security**: expressjs/express (label 5, score 38.1) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: expressjs/express (label 5, score 38.1) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: expressjs/express (label 5, score 38.1) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: expressjs/express (label 5, score 38.1) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **security**: axios/axios (label 5, score 96.5) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: psf/requests (label 5, score 65.9) < gothinkster/flask-realworld-example-app (label 3, score 74.6)
- **security**: psf/requests (label 5, score 65.9) < gothinkster/node-express-realworld-example-app (label 3, score 100.0)
- **security**: psf/requests (label 5, score 65.9) < gothinkster/django-realworld-example-app (label 3, score 80.4)
- **security**: psf/requests (label 5, score 65.9) < mjhea0/flaskr-tdd (label 3, score 77.6)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < adeyosemanputra/pygoat (label 2, score 0.0)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < we45/Vulnerable-Flask-App (label 1, score 0.0)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < anxolerd/dvpwa (label 1, score 0.5)
- **dependencies**: gothinkster/node-express-realworld-example-app (label 3, score 0.1) < anxolerd/dvpwa (label 1, score 0.5)
- **dependencies**: encode/starlette (label 5, score 75.8) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: encode/httpx (label 4, score 34.9) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: pallets/flask (label 5, score 24.3) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: axios/axios (label 5, score 8.4) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: gothinkster/node-express-realworld-example-app (label 3, score 0.1) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: miguelgrinberg/microblog (label 3, score 1.4) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: mjhea0/flaskr-tdd (label 3, score 42.3) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: fastapi/full-stack-fastapi-template (label 5, score 2.0) < appsecco/dvna (label 1, score 100.0)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < snoopysecurity/dvws-node (label 2, score 0.1)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < OWASP/NodeGoat (label 1, score 0.0)
- **dependencies**: pallets/flask (label 5, score 24.3) < mjhea0/flaskr-tdd (label 3, score 42.3)
- **dependencies**: axios/axios (label 5, score 8.4) < mjhea0/flaskr-tdd (label 3, score 42.3)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < gothinkster/flask-realworld-example-app (label 1, score 0.1)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < gothinkster/node-express-realworld-example-app (label 3, score 0.1)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < miguelgrinberg/microblog (label 3, score 1.4)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < gothinkster/django-realworld-example-app (label 1, score 7.1)
- **dependencies**: excalidraw/excalidraw (label 5, score 0.0) < mjhea0/flaskr-tdd (label 3, score 42.3)
- **dependencies**: gothinkster/node-express-realworld-example-app (label 3, score 0.1) < gothinkster/flask-realworld-example-app (label 1, score 0.1)
- **dependencies**: gothinkster/node-express-realworld-example-app (label 3, score 0.1) < gothinkster/django-realworld-example-app (label 1, score 7.1)
- **dependencies**: miguelgrinberg/microblog (label 3, score 1.4) < gothinkster/django-realworld-example-app (label 1, score 7.1)
- **dependencies**: fastapi/full-stack-fastapi-template (label 5, score 2.0) < gothinkster/django-realworld-example-app (label 1, score 7.1)
- **dependencies**: fastapi/full-stack-fastapi-template (label 5, score 2.0) < mjhea0/flaskr-tdd (label 3, score 42.3)
- **architecture**: pallets/flask (label 5, score 48.8) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: encode/django-rest-framework (label 4, score 90.4) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: excalidraw/excalidraw (label 4, score 66.6) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: gothinkster/flask-realworld-example-app (label 4, score 78.7) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: gothinkster/node-express-realworld-example-app (label 4, score 78.0) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: miguelgrinberg/microblog (label 4, score 52.4) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: psf/requests (label 4, score 95.0) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: fastapi/full-stack-fastapi-template (label 5, score 88.5) < adeyosemanputra/pygoat (label 2, score 95.7)
- **architecture**: anxolerd/dvpwa (label 3, score 81.9) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: OWASP/NodeGoat (label 3, score 97.1) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: encode/httpx (label 5, score 96.1) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: pallets/flask (label 5, score 48.8) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: encode/django-rest-framework (label 4, score 90.4) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: excalidraw/excalidraw (label 4, score 66.6) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: gothinkster/flask-realworld-example-app (label 4, score 78.7) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: gothinkster/node-express-realworld-example-app (label 4, score 78.0) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: miguelgrinberg/microblog (label 4, score 52.4) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: gothinkster/django-realworld-example-app (label 3, score 96.1) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: psf/requests (label 4, score 95.0) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: fastapi/full-stack-fastapi-template (label 5, score 88.5) < we45/Vulnerable-Flask-App (label 1, score 98.3)
- **architecture**: pallets/flask (label 5, score 48.8) < anxolerd/dvpwa (label 3, score 81.9)
- **architecture**: encode/httpx (label 5, score 96.1) < appsecco/dvna (label 2, score 97.3)
- **architecture**: pallets/flask (label 5, score 48.8) < appsecco/dvna (label 2, score 97.3)
- **architecture**: encode/django-rest-framework (label 4, score 90.4) < appsecco/dvna (label 2, score 97.3)
- **architecture**: excalidraw/excalidraw (label 4, score 66.6) < appsecco/dvna (label 2, score 97.3)
- **architecture**: gothinkster/flask-realworld-example-app (label 4, score 78.7) < appsecco/dvna (label 2, score 97.3)
- **architecture**: gothinkster/node-express-realworld-example-app (label 4, score 78.0) < appsecco/dvna (label 2, score 97.3)
- **architecture**: miguelgrinberg/microblog (label 4, score 52.4) < appsecco/dvna (label 2, score 97.3)
- **architecture**: psf/requests (label 4, score 95.0) < appsecco/dvna (label 2, score 97.3)
- **architecture**: fastapi/full-stack-fastapi-template (label 5, score 88.5) < appsecco/dvna (label 2, score 97.3)
- **architecture**: pallets/flask (label 5, score 48.8) < snoopysecurity/dvws-node (label 2, score 85.4)
- **architecture**: excalidraw/excalidraw (label 4, score 66.6) < snoopysecurity/dvws-node (label 2, score 85.4)
- **architecture**: gothinkster/flask-realworld-example-app (label 4, score 78.7) < snoopysecurity/dvws-node (label 2, score 85.4)
- **architecture**: gothinkster/node-express-realworld-example-app (label 4, score 78.0) < snoopysecurity/dvws-node (label 2, score 85.4)
- **architecture**: miguelgrinberg/microblog (label 4, score 52.4) < snoopysecurity/dvws-node (label 2, score 85.4)
- **architecture**: encode/httpx (label 5, score 96.1) < OWASP/NodeGoat (label 3, score 97.1)
- **architecture**: pallets/flask (label 5, score 48.8) < OWASP/NodeGoat (label 3, score 97.1)
- **architecture**: fastapi/full-stack-fastapi-template (label 5, score 88.5) < OWASP/NodeGoat (label 3, score 97.1)
- **architecture**: encode/httpx (label 5, score 96.1) < gothinkster/django-realworld-example-app (label 3, score 96.1)
- **architecture**: pallets/flask (label 5, score 48.8) < gothinkster/django-realworld-example-app (label 3, score 96.1)
- **architecture**: pallets/flask (label 5, score 48.8) < mjhea0/flaskr-tdd (label 2, score 82.6)
- **architecture**: excalidraw/excalidraw (label 4, score 66.6) < mjhea0/flaskr-tdd (label 2, score 82.6)
- **architecture**: gothinkster/flask-realworld-example-app (label 4, score 78.7) < mjhea0/flaskr-tdd (label 2, score 82.6)
- **architecture**: gothinkster/node-express-realworld-example-app (label 4, score 78.0) < mjhea0/flaskr-tdd (label 2, score 82.6)
- **architecture**: miguelgrinberg/microblog (label 4, score 52.4) < mjhea0/flaskr-tdd (label 2, score 82.6)
- **architecture**: fastapi/full-stack-fastapi-template (label 5, score 88.5) < gothinkster/django-realworld-example-app (label 3, score 96.1)
- **code_health**: gothinkster/django-realworld-example-app (label 3, score 90.4) < we45/Vulnerable-Flask-App (label 1, score 95.2)
- **code_health**: psf/requests (label 4, score 92.6) < we45/Vulnerable-Flask-App (label 1, score 95.2)
- **code_health**: encode/starlette (label 5, score 96.1) < gothinkster/flask-realworld-example-app (label 3, score 98.8)
- **code_health**: encode/starlette (label 5, score 96.1) < mjhea0/flaskr-tdd (label 3, score 99.7)
- **code_health**: encode/httpx (label 5, score 97.2) < gothinkster/flask-realworld-example-app (label 3, score 98.8)
- **code_health**: encode/httpx (label 5, score 97.2) < mjhea0/flaskr-tdd (label 3, score 99.7)
- **code_health**: pallets/flask (label 5, score 97.5) < gothinkster/flask-realworld-example-app (label 3, score 98.8)
- **code_health**: pallets/flask (label 5, score 97.5) < mjhea0/flaskr-tdd (label 3, score 99.7)
- **code_health**: fastapi/full-stack-fastapi-template (label 5, score 98.2) < gothinkster/flask-realworld-example-app (label 3, score 98.8)
- **code_health**: fastapi/full-stack-fastapi-template (label 5, score 98.2) < mjhea0/flaskr-tdd (label 3, score 99.7)
- **overall**: miguelgrinberg/microblog (label 4, score 38.6) < we45/Vulnerable-Flask-App (label 1, score 43.0)
- **overall**: pallets/flask (label 5, score 57.6) < anxolerd/dvpwa (label 1, score 68.8)
- **overall**: excalidraw/excalidraw (label 4, score 59.2) < anxolerd/dvpwa (label 1, score 68.8)
- **overall**: miguelgrinberg/microblog (label 4, score 38.6) < anxolerd/dvpwa (label 1, score 68.8)
- **overall**: pallets/flask (label 5, score 57.6) < appsecco/dvna (label 1, score 59.2)
- **overall**: excalidraw/excalidraw (label 4, score 59.2) < appsecco/dvna (label 1, score 59.2)
- **overall**: miguelgrinberg/microblog (label 4, score 38.6) < appsecco/dvna (label 1, score 59.2)
- **overall**: encode/httpx (label 5, score 73.5) < mjhea0/flaskr-tdd (label 3, score 76.0)
- **overall**: pallets/flask (label 5, score 57.6) < gothinkster/flask-realworld-example-app (label 2, score 65.4)
- **overall**: pallets/flask (label 5, score 57.6) < gothinkster/node-express-realworld-example-app (label 3, score 69.5)
- **overall**: pallets/flask (label 5, score 57.6) < gothinkster/django-realworld-example-app (label 2, score 70.9)
- **overall**: pallets/flask (label 5, score 57.6) < mjhea0/flaskr-tdd (label 3, score 76.0)
- **overall**: encode/django-rest-framework (label 5, score 74.1) < mjhea0/flaskr-tdd (label 3, score 76.0)
- **overall**: expressjs/express (label 5, score 69.1) < gothinkster/node-express-realworld-example-app (label 3, score 69.5)
- **overall**: expressjs/express (label 5, score 69.1) < gothinkster/django-realworld-example-app (label 2, score 70.9)
- **overall**: expressjs/express (label 5, score 69.1) < mjhea0/flaskr-tdd (label 3, score 76.0)
- **overall**: axios/axios (label 5, score 75.1) < mjhea0/flaskr-tdd (label 3, score 76.0)
- **overall**: excalidraw/excalidraw (label 4, score 59.2) < gothinkster/flask-realworld-example-app (label 2, score 65.4)
- **overall**: excalidraw/excalidraw (label 4, score 59.2) < gothinkster/django-realworld-example-app (label 2, score 70.9)
- **overall**: miguelgrinberg/microblog (label 4, score 38.6) < gothinkster/flask-realworld-example-app (label 2, score 65.4)
- **overall**: miguelgrinberg/microblog (label 4, score 38.6) < gothinkster/django-realworld-example-app (label 2, score 70.9)
- **overall**: fastapi/full-stack-fastapi-template (label 5, score 75.3) < mjhea0/flaskr-tdd (label 3, score 76.0)

## Sensitivity (ρ with one parameter changed)

| Variant | security | dependencies | architecture | code_health | overall |
|---|---|---|---|---|---|
| **as shipped** | 0.32 | 0.43 | -0.16 | 0.34 | 0.66 |
| security weight ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.60 |
| security half-life ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.62 |
| security weight ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.61 |
| security half-life ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.68 |
| dependencies weight ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.58 |
| dependencies half-life ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.67 |
| dependencies weight ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.68 |
| dependencies half-life ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.67 |
| architecture weight ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.70 |
| architecture half-life ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.66 |
| architecture weight ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.65 |
| architecture half-life ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.68 |
| code_health weight ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.67 |
| code_health half-life ×0.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.67 |
| code_health weight ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.66 |
| code_health half-life ×1.5 | 0.32 | 0.43 | -0.16 | 0.34 | 0.64 |
| repeat damping exponent 0.5 | 0.27 | 0.43 | -0.12 | 0.24 | 0.55 |
| repeat damping exponent 1.0 | 0.34 | 0.43 | -0.17 | 0.34 | 0.73 |
| no repeat damping (exponent 0) | -0.25 | 0.41 | -0.18 | 0.13 | 0.10 |
| test-path factor 0.05 | 0.32 | 0.43 | -0.16 | 0.36 | 0.70 |
| test-path factor 1.0 | 0.32 | 0.31 | -0.16 | 0.20 | 0.60 |
| corroboration factor 1.0 | 0.31 | 0.43 | -0.16 | 0.34 | 0.63 |
| equal category weights | 0.32 | 0.43 | -0.16 | 0.34 | 0.60 |
| flat severity weights | 0.13 | 0.42 | 0.07 | 0.20 | 0.68 |
| no size normalisation | 0.14 | 0.43 | -0.28 | -0.14 | 0.36 |

## Counterfactual experiments (not shipped; same labels, same snapshot)

| Experiment | security | dependencies | architecture | code_health | overall |
|---|---|---|---|---|---|
| **as shipped (v1.0)** | 0.32 | 0.43 | -0.16 | 0.34 | 0.66 |
| E1 unpinned dependencies not assessed | 0.32 | 0.49 (n=17) | -0.16 | 0.34 | 0.61 |
| E2 advisories grouped per package | 0.32 | 0.39 | -0.16 | 0.34 | 0.66 |
| E3 examples/docs weighted like tests | 0.39 | 0.45 | -0.16 | 0.34 | 0.74 |
| E4 cycles counted per component | 0.32 | 0.43 | -0.02 | 0.34 | 0.72 |
| E1–E4 combined | 0.39 | 0.45 (n=17) | -0.02 | 0.34 | 0.78 |

Combined, with 95% bootstrap CIs: security 0.39 [-0.12, 0.74]; dependencies 0.45 [-0.08, 0.85]; architecture -0.02 [-0.49, 0.41]; code_health 0.34 [-0.34, 0.79]; overall 0.78 [0.50, 0.91]. Inversions: 115 (as shipped: 141).

Combined, within groups: vulnerable: overall n/a, security n/a; tutorial: overall -0.32, security -0.71; mature: overall 0.55, security -0.52.

## Import resolution coverage (architecture analyzer)

Median 100.0%, lowest 95.3%.

| Repository | Coverage | Unresolved by reason |
|---|---|---|
| OWASP/NodeGoat | 95.3% | {"file not found": 1, "dynamic import with a non-literal specifier": 2} |
| pallets/flask | 97.1% | {"relative import beyond the top-level package": 17, "dynamic import with a non-literal module name": 2} |
| axios/axios | 99.0% | {"file not found": 6, "dynamic import with a non-literal specifier": 1} |
| expressjs/express | 99.3% | {"dynamic import with a non-literal specifier": 3} |
| psf/requests | 99.4% | {"dynamic import with a non-literal module name": 2} |
| encode/django-rest-framework | 99.8% | {"dynamic import with a non-literal module name": 2} |
| excalidraw/excalidraw | 99.8% | {"file not found": 1, "dynamic import with a non-literal specifier": 8} |
| adeyosemanputra/pygoat | 100.0% | {} |
| anxolerd/dvpwa | 100.0% | {} |
| appsecco/dvna | 100.0% | {} |
| encode/httpx | 100.0% | {} |
| encode/starlette | 100.0% | {} |
| fastapi/full-stack-fastapi-template | 100.0% | {} |
| gothinkster/django-realworld-example-app | 100.0% | {} |
| gothinkster/flask-realworld-example-app | 100.0% | {} |
| gothinkster/node-express-realworld-example-app | 100.0% | {} |
| miguelgrinberg/microblog | 100.0% | {} |
| mjhea0/flaskr-tdd | 100.0% | {} |
| snoopysecurity/dvws-node | 100.0% | {} |
| we45/Vulnerable-Flask-App | 100.0% | {} |
