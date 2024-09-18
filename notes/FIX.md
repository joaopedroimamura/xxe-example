# Defense

XXE vulnerabilities arise because the application's XML parsing library supports potentially dangerous XML features that the application does not need or intend to use. The easiest and most effective way to prevent XXE attack is to disable those features.

Generally, it is sufficient to disable resolution of external entities and disable support for ```XInclude```. This can usually be done via configuration options or by programatically overriding default behavior.