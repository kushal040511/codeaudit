# Phishing risk validation — dataset-20260917.results.jsonl

Model version: 0.1-prior. 288 URLs evaluated; 189 scored (98 phishing, 91 legitimate).

## Reachability

| State | Phishing | Legitimate |
|---|---|---|
| ok | 98 | 91 |
| unreachable | 14 | 26 |
| dead_http | 35 | 16 |
| taken_down | 2 | 0 |
| blocked | 0 | 1 |
| error | 1 | 4 |

52 of 150 phishing URLs (35%) were no longer serving a phishing page when checked.

Most common non-ok reasons:

- dead_http: HTTP 403 ×27
- dead_http: HTTP 404 ×14
- dead_http: HTTP 451 ×5
- unreachable: The page could not be loaded (Page.goto: net::ERR_TUNNEL_CONNECTION_FA ×3
- unreachable: empty page ×3
- error: The page could not be loaded (Page.goto: net::ERR_HTTP2_PROTOCOL_ERROR ×2
- taken_down: Account Suspended ×1
- unreachable: wrtgnjuyt.xyz could not be resolved. ×1

## Metrics: without reputation (headline)

ROC AUC **0.901**. Best F1 0.892 at score ≥ 1 (precision 0.897, recall 0.888, false positive rate 0.110).

| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| ≥20 (moderate) | 0.923 | 0.367 | 0.526 | 0.033 | 36 | 3 | 62 | 88 |
| ≥45 (high) | 0.875 | 0.071 | 0.132 | 0.011 | 7 | 1 | 91 | 90 |
| ≥70 (very_high) | n/a | 0.000 | 0.000 | 0.000 | 0 | 0 | 98 | 91 |

## Metrics: full score (inflated: labels come from the same feeds)

ROC AUC **0.999**. Best F1 0.995 at score ≥ 31 (precision 0.990, recall 1.000, false positive rate 0.011).

| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| ≥20 (moderate) | 0.970 | 1.000 | 0.985 | 0.033 | 98 | 3 | 0 | 88 |
| ≥45 (high) | 0.990 | 1.000 | 0.995 | 0.011 | 98 | 1 | 0 | 90 |
| ≥70 (very_high) | 1.000 | 0.500 | 0.667 | 0.000 | 49 | 0 | 49 | 91 |

ROC curves: `roc.svg`; per-threshold values: `roc-*.csv`.

## Signals

Fire rates, precision when fired, AUC lost when the signal's points are removed (headline score), and a regularised logistic-regression coefficient fitted on these labels (log-odds; larger = more predictive).

| Signal | Points | On phishing | On legitimate | Precision | AUC drop | Logistic coef. | Verdict |
|---|---|---|---|---|---|---|---|
| hosting_platform | +6 | 46% | 0% | 1.00 | +0.0991 | 1.096 | predictive |
| domain_age_over_3y | -8 | 17% | 82% | 0.18 | +0.0536 | -0.976 | predictive (trust signal) |
| no_mx_record | +3 | 35% | 14% | 0.72 | +0.0249 | 0.537 | predictive |
| tld_elevated_risk | +4 | 8% | 4% | 0.67 | +0.0109 | 0.251 | predictive |
| brand_in_title | +15 | 24% | 0% | 1.00 | +0.0082 | 0.501 | predictive |
| domain_age_under_1y | +4 | 9% | 0% | 1.00 | +0.0058 | 0.352 | predictive |
| no_https | +8 | 7% | 0% | 1.00 | +0.0053 | 0.266 | predictive |
| cert_new | +5 | 11% | 9% | 0.58 | +0.0049 | 0.036 | weak |
| favicon_match | +30 | 1% | 1% | 0.50 | +0.0031 | 0.088 | too rare to judge |
| brand_in_domain | +20 | 11% | 0% | 1.00 | +0.0019 | 0.185 | discriminative but redundant with other signals |
| domain_age_under_7d | +25 | 5% | 0% | 1.00 | +0.0013 | 0.178 | discriminative but redundant with other signals |
| domain_age_under_30d | +18 | 2% | 0% | 1.00 | +0.0010 | 0.084 | too rare to judge |
| domain_age_under_90d | +10 | 2% | 0% | 1.00 | +0.0010 | 0.083 | too rare to judge |
| brand_in_subdomain | +18 | 1% | 0% | 1.00 | +0.0002 | 0.091 | too rare to judge |
| credentials_cross_domain_form | +22 | 1% | 0% | 1.00 | +0.0002 | 0.023 | too rare to judge |
| payment_fields | +10 | 1% | 0% | 1.00 | +0.0002 | 0.028 | too rare to judge |
| sensitive_fields_insecure | +15 | 1% | 0% | 1.00 | +0.0002 | 0.036 | too rare to judge |
| links_to_brand | +15 | 1% | 0% | 1.00 | +0.0001 | 0.024 | too rare to judge |
| reputation_openphish_url | +60 | 100% | 0% | 1.00 | +0.0000 | 4.753 | leaks labels (excluded from headline metrics) |
| tld_high_risk | +8 | 2% | 0% | 1.00 | +0.0000 | 0.081 | too rare to judge |
| brand_in_text_with_credentials | +8 | 4% | 1% | 0.80 | -0.0007 | -0.017 | discriminative but redundant with other signals |
| cert_untrusted | +12 | 2% | 1% | 0.67 | -0.0015 | -0.016 | weak |
| cert_hostname_mismatch | +15 | 2% | 1% | 0.67 | -0.0016 | -0.016 | weak |
| cross_domain_redirect | +4 | 10% | 8% | 0.59 | -0.0028 | 0.108 | weak |
| visual_match_strong | +35 | 0% | 1% | 0.00 | -0.0030 | -0.061 | too rare to judge |
| password_field | +8 | 28% | 18% | 0.63 | -0.0036 | 0.21 | weak |

## False positives (legitimate sites scoring ≥ 1, without reputation)

- **60** `hxxps://www[.]gov[.]uk/government/organisations/hm-revenue-customs` (brand_official): 100% visual similarity to the HMRC home page (+35); Favicon is identical to HMRC's (+30); Domain registered 13 years ago (-8); www.gov.uk has no mail (MX) records (+3)
- **30** `hxxps://tfkc[.]de/` (tranco): Certificate names don't match the domain (+15); Certificate is not trusted (Hostname mismatch, certificate is not valid for 'tfkc.de'.) (+12); tfkc.de has no mail (MX) records (+3)
- **24** `hxxps://komikindo[.]ch/` (tranco): The page asks for a password (+8); Page mentions Facebook and asks for credentials, on a non-Facebook domain (+8); Certificate issued 0 days ago (+5); komikindo.ch has no mail (MX) records (+3)
- **12** `hxxps://sina[.]com[.]cn/` (tranco): The page asks for a password (+8); .cn has elevated abuse rates (+4)
- **11** `hxxps://uakinogo[.]io/` (tranco): The page asks for a password (+8); uakinogo.io has no mail (MX) records (+3)
- **5** `hxxps://wvu[.]edu/` (tranco): Certificate issued 4 days ago (+5)
- **5** `hxxps://lu[.]se/` (tranco): Certificate issued 1 day ago (+5)
- **4** `hxxps://login[.]microsoftonline[.]com/` (brand_official): The page asks for a password (+8); Domain registered 24 years ago (-8); Redirected across domains: microsoftonline.com → office.com (+4)
- **4** `hxxps://jivox[.]com/` (tranco): Redirected across domains: jivox.com → davincicommerce.ai (+4)
- **4** `hxxps://doxygen[.]org/` (tranco): Domain registered 20 years ago (-8); Certificate issued 0 days ago (+5); Redirected across domains: doxygen.org → doxygen.nl (+4); doxygen.nl has no mail (MX) records (+3)

## False negatives (phishing scoring < 45, without reputation): 91

- 0 `hxxp://www[.]kucoin-leggn[.]godaddysites[.]com/`: domain_age_over_3y (-8)
- 0 `hxxps://m[.]ag888[.]vip/chs/`: domain_age_over_3y (-8), tld_elevated_risk (+4), no_mx_record (+3)
- 0 `hxxps://eu-assets[.]contentstack[.]com/v3/assets/blt6958cd33d4a587e3/bltd8225ce9fcef7a6b/6a8d58...`: password_field (+8), domain_age_over_3y (-8)
- 0 `hxxp://www[.]signintoxfinitycomcast[.]weebly[.]com/`: domain_age_over_3y (-8)
- 0 `hxxps://docuposte[.]secure-mailing-service[.]com/index/2cb7dcf1d1b642e69c9b21de8225ec9b/d7c0aacb20c724345...`: domain_age_over_3y (-8), cert_new (+5), no_mx_record (+3)
- 0 `hxxps://friesehoenderclub[.]nl/assets/images/zim/`: password_field (+8), domain_age_over_3y (-8)
- 0 `hxxps://multistore-lb[.]com/docsign/pdf.html`: no signals fired
- 0 `hxxps://demo[.]beamon[.]com/.well-known/wp-admin/`: domain_age_over_3y (-8)
- 0 `hxxps://xfinity-555[.]weeblysite[.]com/`: domain_age_over_3y (-8), no_mx_record (+3)
- 0 `hxxps://ecloud4u[.]eu/`: no signals fired
- 0 `hxxps://cx3liveo[.]sviluppo[.]host/sessLSK/StrJ9/oev3/ATstr/`: domain_age_over_3y (-8), cross_domain_redirect (+4)
- 3 `hxxp://robiox[.]com[.]ps/communities/8692908357/Shy-clothing`: no_mx_record (+3)
- 3 `hxxps://www[.]roblox[.]et/users/9925730885/profile`: no_mx_record (+3)
- 3 `hxxps://www[.]roblox[.]com[.]bi/users/857039033623/profile`: no_mx_record (+3)
- 3 `hxxp://roblox[.]com[.]hr/communities/3764020621/Murderzxc`: no_mx_record (+3)
- 3 `hxxps://spectrum[.]hirevue-app[.]com/guest/ce/foyers/now/Event.aspx`: no_mx_record (+3)
- 4 `hxxp://webmail-ionos-app-suite-supreme-guide-production[.]up[.]railway[.]app/`: password_field (+8), domain_age_over_3y (-8), tld_elevated_risk (+4)
- 4 `hxxp://sr[.]swka[.]eu[.]cc/ng/`: domain_age_over_3y (-8), cert_new (+5), tld_elevated_risk (+4), no_mx_record (+3)
- 4 `hxxps://dhofareng[.]com/docusign/Mac/utility.php`: domain_age_under_1y (+4)
- 5 `hxxps://upholdlogeiin[.]gitbook[.]io/us`: cert_new (+5)
- 6 `hxxp://www[.]adsbot2-eauj[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://business-metta-platform[.]vercel[.]app/privacy`: hosting_platform (+6)
- 6 `hxxps://www[.]meta-verified-blueticks-fb11[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxp://www[.]pasantha[.]vercel[.]app/`: hosting_platform (+6)
- 6 `hxxps://fb-meta-verified-92745[.]vercel[.]app/`: hosting_platform (+6)
