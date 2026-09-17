# Phishing risk validation — dataset-20260917-rerun.results.jsonl

Model version: 0.1.1-prior. 189 URLs evaluated; 188 scored (98 phishing, 90 legitimate).

## Reachability

| State | Phishing | Legitimate |
|---|---|---|
| ok | 98 | 90 |
| unreachable | 0 | 0 |
| dead_http | 0 | 0 |
| taken_down | 0 | 0 |
| blocked | 0 | 0 |
| error | 0 | 1 |

0 of 98 phishing URLs (0%) were no longer serving a phishing page when checked.

Most common non-ok reasons:

- error: The page used more memory than the capture limit allows. ×1

## Metrics: without reputation (headline)

ROC AUC **0.927**. Best F1 0.914 at score ≥ 1 (precision 0.909, recall 0.918, false positive rate 0.100).

| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| ≥20 (moderate) | 0.949 | 0.378 | 0.540 | 0.022 | 37 | 2 | 61 | 88 |
| ≥45 (high) | 1.000 | 0.082 | 0.151 | 0.000 | 8 | 0 | 90 | 90 |
| ≥70 (very_high) | n/a | 0.000 | 0.000 | 0.000 | 0 | 0 | 98 | 90 |

## Metrics: full score (inflated: labels come from the same feeds)

ROC AUC **1.000**. Best F1 1.000 at score ≥ 31 (precision 1.000, recall 1.000, false positive rate 0.000).

| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| ≥20 (moderate) | 0.980 | 1.000 | 0.990 | 0.022 | 98 | 2 | 0 | 88 |
| ≥45 (high) | 1.000 | 1.000 | 1.000 | 0.000 | 98 | 0 | 0 | 90 |
| ≥70 (very_high) | 1.000 | 0.520 | 0.685 | 0.000 | 51 | 0 | 47 | 90 |

ROC curves: `roc.svg`; per-threshold values: `roc-*.csv`.

## Signals

Fire rates, precision when fired, AUC lost when the signal's points are removed (headline score), and a regularised logistic-regression coefficient fitted on these labels (log-odds; larger = more predictive).

| Signal | Points | On phishing | On legitimate | Precision | AUC drop | Logistic coef. | Verdict |
|---|---|---|---|---|---|---|---|
| hosting_platform | +6 | 51% | 0% | 1.00 | +0.1159 | 1.186 | predictive |
| domain_age_over_3y | -8 | 10% | 82% | 0.12 | +0.0552 | -1.143 | predictive (trust signal) |
| no_mx_record | +3 | 34% | 14% | 0.72 | +0.0251 | 0.576 | predictive |
| tld_elevated_risk | +4 | 7% | 4% | 0.64 | +0.0061 | 0.223 | predictive |
| domain_age_under_1y | +4 | 9% | 0% | 1.00 | +0.0058 | 0.381 | predictive |
| favicon_match | +30 | 1% | 0% | 1.00 | +0.0056 | 0.176 | too rare to judge |
| no_https | +8 | 7% | 0% | 1.00 | +0.0054 | 0.309 | predictive |
| brand_in_title | +15 | 24% | 0% | 1.00 | +0.0029 | 0.489 | discriminative but redundant with other signals |
| brand_in_domain | +20 | 11% | 0% | 1.00 | +0.0018 | 0.192 | discriminative but redundant with other signals |
| domain_age_under_7d | +25 | 5% | 0% | 1.00 | +0.0012 | 0.184 | discriminative but redundant with other signals |
| cert_new | +5 | 11% | 7% | 0.65 | +0.0010 | 0.082 | weak |
| domain_age_under_30d | +18 | 2% | 0% | 1.00 | +0.0010 | 0.09 | too rare to judge |
| domain_age_under_90d | +10 | 2% | 0% | 1.00 | +0.0010 | 0.089 | too rare to judge |
| brand_in_subdomain | +18 | 1% | 0% | 1.00 | +0.0002 | 0.113 | too rare to judge |
| credentials_cross_domain_form | +22 | 1% | 0% | 1.00 | +0.0002 | 0.025 | too rare to judge |
| payment_fields | +10 | 1% | 0% | 1.00 | +0.0002 | 0.029 | too rare to judge |
| sensitive_fields_insecure | +15 | 1% | 0% | 1.00 | +0.0002 | 0.038 | too rare to judge |
| links_to_brand | +15 | 1% | 0% | 1.00 | +0.0001 | 0.026 | too rare to judge |
| reputation_openphish_url | +60 | 100% | 0% | 1.00 | +0.0000 | 4.569 | leaks labels (excluded from headline metrics) |
| tld_high_risk | +8 | 2% | 0% | 1.00 | +0.0000 | 0.085 | too rare to judge |
| brand_in_text_with_credentials | +8 | 4% | 1% | 0.80 | -0.0007 | -0.058 | discriminative but redundant with other signals |
| cert_untrusted | +12 | 2% | 1% | 0.67 | -0.0016 | -0.046 | weak |
| cert_hostname_mismatch | +15 | 2% | 1% | 0.67 | -0.0018 | -0.046 | weak |
| cross_domain_redirect | +4 | 10% | 8% | 0.59 | -0.0022 | 0.154 | weak |
| password_field | +8 | 28% | 18% | 0.63 | -0.0090 | 0.215 | weak |

## False positives (legitimate sites scoring ≥ 1, without reputation)

- **30** `hxxps://tfkc[.]de/` (tranco): Certificate names don't match the domain (+15); Certificate is not trusted (Hostname mismatch, certificate is not valid for 'tfkc.de'.) (+12); tfkc.de has no mail (MX) records (+3)
- **24** `hxxps://komikindo[.]ch/` (tranco): The page asks for a password (+8); Page mentions Facebook and asks for credentials, on a non-Facebook domain (+8); Certificate issued 0 days ago (+5); komikindo.ch has no mail (MX) records (+3)
- **12** `hxxps://sina[.]com[.]cn/` (tranco): The page asks for a password (+8); .cn has elevated abuse rates (+4)
- **11** `hxxps://uakinogo[.]io/` (tranco): The page asks for a password (+8); uakinogo.io has no mail (MX) records (+3)
- **5** `hxxps://wvu[.]edu/` (tranco): Certificate issued 4 days ago (+5)
- **5** `hxxps://lu[.]se/` (tranco): Certificate issued 1 day ago (+5)
- **4** `hxxps://login[.]microsoftonline[.]com/` (brand_official): The page asks for a password (+8); Domain registered 24 years ago (-8); Redirected across domains: microsoftonline.com → office.com (+4)
- **4** `hxxps://jivox[.]com/` (tranco): Redirected across domains: jivox.com → davincicommerce.ai (+4)
- **4** `hxxps://doxygen[.]org/` (tranco): Domain registered 20 years ago (-8); Certificate issued 0 days ago (+5); Redirected across domains: doxygen.org → doxygen.nl (+4); doxygen.nl has no mail (MX) records (+3)

## False negatives (phishing scoring < 45, without reputation): 90

- 0 `hxxps://m[.]ag888[.]vip/chs/`: domain_age_over_3y (-8), tld_elevated_risk (+4), no_mx_record (+3)
- 0 `hxxps://eu-assets[.]contentstack[.]com/v3/assets/blt6958cd33d4a587e3/bltd8225ce9fcef7a6b/6a8d58...`: password_field (+8), domain_age_over_3y (-8)
- 0 `hxxps://docuposte[.]secure-mailing-service[.]com/index/2cb7dcf1d1b642e69c9b21de8225ec9b/d7c0aacb20c724345...`: domain_age_over_3y (-8), cert_new (+5), no_mx_record (+3)
- 0 `hxxps://friesehoenderclub[.]nl/assets/images/zim/`: password_field (+8), domain_age_over_3y (-8)
- 0 `hxxps://multistore-lb[.]com/docsign/pdf.html`: no signals fired
- 0 `hxxps://demo[.]beamon[.]com/.well-known/wp-admin/`: domain_age_over_3y (-8)
- 0 `hxxps://ecloud4u[.]eu/`: no signals fired
- 0 `hxxps://cx3liveo[.]sviluppo[.]host/sessLSK/StrJ9/oev3/ATstr/`: domain_age_over_3y (-8), cross_domain_redirect (+4)
- 3 `hxxp://robiox[.]com[.]ps/communities/8692908357/Shy-clothing`: no_mx_record (+3)
- 3 `hxxps://www[.]roblox[.]et/users/9925730885/profile`: no_mx_record (+3)
- 3 `hxxps://www[.]roblox[.]com[.]bi/users/857039033623/profile`: no_mx_record (+3)
- 3 `hxxp://roblox[.]com[.]hr/communities/3764020621/Murderzxc`: no_mx_record (+3)
- 3 `hxxps://spectrum[.]hirevue-app[.]com/guest/ce/foyers/now/Event.aspx`: no_mx_record (+3)
- 4 `hxxp://sr[.]swka[.]eu[.]cc/ng/`: domain_age_over_3y (-8), cert_new (+5), tld_elevated_risk (+4), no_mx_record (+3)
- 4 `hxxps://dhofareng[.]com/docusign/Mac/utility.php`: domain_age_under_1y (+4)
- 6 `hxxp://www[.]adsbot2-eauj[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://business-metta-platform[.]vercel[.]app/privacy`: hosting_platform (+6)
- 6 `hxxp://www[.]kucoin-leggn[.]godaddysites[.]com/`: hosting_platform (+6)
- 6 `hxxps://www[.]meta-verified-blueticks-fb11[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxp://www[.]pasantha[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxp://www[.]signintoxfinitycomcast[.]weebly[.]com/`: hosting_platform (+6)
- 6 `hxxps://fb-meta-verified-92745[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://jquery-tawny[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://apppaficicos[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://www[.]trustwallet-secure-check[.]vercel[.]app/`: hosting_platform (+6)
