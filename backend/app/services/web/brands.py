"""Commonly impersonated brands: official domains, names, and reference pages.

Sources for the selection: the most-impersonated brands in public phishing reports
(APWG, Check Point, Vade, Cloudflare brand impersonation reports, 2023-2025).
Reference pages include the login page, not just the homepage, because clones
usually copy the login page.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    key: str
    name: str
    # Registrable domains the brand legitimately uses.
    domains: tuple[str, ...]
    # Case-insensitive whole-word names looked for in page titles and text.
    keywords: tuple[str, ...]
    # (page, url) pairs captured into the visual reference set.
    references: tuple[tuple[str, str], ...]

    @property
    def labels(self) -> tuple[str, ...]:
        """Second-level labels used for typosquatting checks, e.g. "paypal"."""
        return tuple(
            dict.fromkeys(d.split(".")[0] for d in self.domains if len(d.split(".")[0]) >= 4)
        )


BRANDS: tuple[Brand, ...] = (
    Brand(
        "paypal",
        "PayPal",
        ("paypal.com", "paypal.me", "paypalobjects.com"),
        ("paypal",),
        (("home", "https://www.paypal.com/"), ("login", "https://www.paypal.com/signin")),
    ),
    Brand(
        "microsoft",
        "Microsoft",
        (
            "microsoft.com",
            "microsoftonline.com",
            "live.com",
            "office.com",
            "outlook.com",
            "office365.com",
            "sharepoint.com",
            "onedrive.com",
            "msauth.net",
        ),
        ("microsoft", "office 365", "microsoft 365", "outlook", "onedrive", "sharepoint"),
        (("home", "https://www.microsoft.com/"), ("login", "https://login.microsoftonline.com/")),
    ),
    Brand(
        "apple",
        "Apple",
        ("apple.com", "icloud.com"),
        ("apple id", "icloud", "apple"),
        (("home", "https://www.apple.com/"), ("login", "https://www.icloud.com/")),
    ),
    Brand(
        "google",
        "Google",
        ("google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com"),
        ("google", "gmail"),
        (("home", "https://www.google.com/"), ("login", "https://accounts.google.com/")),
    ),
    Brand(
        "amazon",
        "Amazon",
        (
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.in",
            "amazonaws.com",
            "media-amazon.com",
        ),
        ("amazon",),
        (
            ("home", "https://www.amazon.com/"),
            (
                "login",
                "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
            ),
        ),
    ),
    Brand(
        "netflix",
        "Netflix",
        ("netflix.com", "nflxext.com"),
        ("netflix",),
        (("home", "https://www.netflix.com/"), ("login", "https://www.netflix.com/login")),
    ),
    Brand(
        "facebook",
        "Facebook",
        ("facebook.com", "fb.com", "fbcdn.net"),
        ("facebook",),
        (("home", "https://www.facebook.com/"),),
    ),
    Brand(
        "instagram",
        "Instagram",
        ("instagram.com", "cdninstagram.com"),
        ("instagram",),
        (("login", "https://www.instagram.com/accounts/login/"),),
    ),
    Brand(
        "whatsapp",
        "WhatsApp",
        ("whatsapp.com", "whatsapp.net"),
        ("whatsapp",),
        (("home", "https://www.whatsapp.com/"), ("web", "https://web.whatsapp.com/")),
    ),
    Brand(
        "linkedin",
        "LinkedIn",
        ("linkedin.com", "licdn.com"),
        ("linkedin",),
        (("login", "https://www.linkedin.com/login"),),
    ),
    Brand("dhl", "DHL", ("dhl.com", "dhl.de"), ("dhl",), (("home", "https://www.dhl.com/"),)),
    Brand("fedex", "FedEx", ("fedex.com",), ("fedex",), (("home", "https://www.fedex.com/"),)),
    Brand("ups", "UPS", ("ups.com",), ("ups",), (("home", "https://www.ups.com/"),)),
    Brand("usps", "USPS", ("usps.com",), ("usps",), (("home", "https://www.usps.com/"),)),
    Brand(
        "chase",
        "Chase",
        ("chase.com", "jpmorganchase.com"),
        ("chase bank", "jpmorgan chase"),
        (("home", "https://www.chase.com/"),),
    ),
    Brand(
        "bankofamerica",
        "Bank of America",
        ("bankofamerica.com", "bofa.com"),
        ("bank of america",),
        (("home", "https://www.bankofamerica.com/"),),
    ),
    Brand(
        "wellsfargo",
        "Wells Fargo",
        ("wellsfargo.com", "wf.com"),
        ("wells fargo",),
        (("home", "https://www.wellsfargo.com/"),),
    ),
    Brand(
        "coinbase",
        "Coinbase",
        ("coinbase.com",),
        ("coinbase",),
        (("home", "https://www.coinbase.com/"), ("login", "https://login.coinbase.com/signin")),
    ),
    Brand(
        "binance",
        "Binance",
        ("binance.com",),
        ("binance",),
        (("home", "https://www.binance.com/en"),),
    ),
    Brand(
        "metamask", "MetaMask", ("metamask.io",), ("metamask",), (("home", "https://metamask.io/"),)
    ),
    Brand(
        "dropbox",
        "Dropbox",
        ("dropbox.com", "dropboxusercontent.com"),
        ("dropbox",),
        (("login", "https://www.dropbox.com/login"),),
    ),
    Brand(
        "docusign",
        "DocuSign",
        ("docusign.com", "docusign.net"),
        ("docusign",),
        (("home", "https://www.docusign.com/"),),
    ),
    Brand(
        "adobe",
        "Adobe",
        ("adobe.com", "adobelogin.com"),
        ("adobe",),
        (("home", "https://www.adobe.com/"),),
    ),
    Brand("att", "AT&T", ("att.com", "att.net"), ("at&t",), (("home", "https://www.att.com/"),)),
    Brand(
        "steam",
        "Steam",
        ("steampowered.com", "steamcommunity.com"),
        ("steam",),
        (("login", "https://store.steampowered.com/login/"),),
    ),
    Brand(
        "ebay",
        "eBay",
        ("ebay.com", "ebay.co.uk", "ebayimg.com"),
        ("ebay",),
        (("home", "https://www.ebay.com/"),),
    ),
    Brand(
        "wetransfer",
        "WeTransfer",
        ("wetransfer.com", "we.tl"),
        ("wetransfer",),
        (("home", "https://wetransfer.com/"),),
    ),
    Brand(
        "yahoo",
        "Yahoo",
        ("yahoo.com", "yimg.com"),
        ("yahoo",),
        (("login", "https://login.yahoo.com/"),),
    ),
    Brand(
        "irs",
        "IRS",
        ("irs.gov",),
        ("internal revenue service",),
        (("home", "https://www.irs.gov/"),),
    ),
    Brand(
        "hmrc",
        "HMRC",
        # gov.uk is a public suffix: list the hosts HMRC actually uses.
        ("www.gov.uk", "hmrc.gov.uk", "tax.service.gov.uk"),
        ("hmrc",),
        (("home", "https://www.gov.uk/government/organisations/hm-revenue-customs"),),
    ),
)
BRANDS_BY_KEY = {brand.key: brand for brand in BRANDS}


def brand_for_domain(registrable: str, host: str | None = None) -> Brand | None:
    """The brand that officially owns `registrable` (or `host`, for brands whose domain
    sits under a public suffix such as gov.uk), if any."""
    for brand in BRANDS:
        if registrable in brand.domains:
            return brand
        if host and any(host == d or host.endswith(f".{d}") for d in brand.domains):
            return brand
    return None
