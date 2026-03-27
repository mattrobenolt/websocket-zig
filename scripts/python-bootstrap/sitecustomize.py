import os
import site

site_packages = os.environ.get("AUTOBAHN_SITE_PACKAGES")
if site_packages:
    site.addsitedir(site_packages)
