"""Audit of every fabricx render for image pull secrets (live S16: the gateway Deployment had no imagePullSecrets for the PRIVATE package rdbi-node-ci; bank-b/bi passed only through a node cache).

Rules: (1) renders that emit pods of OUR private images (fsc, gw, ceremony) must set `imagePullSecrets: ghcr-pull` in their pod specs; (2) renders of upstream images (arma, committer, fca) may only name
PUBLIC registries/repositories (docker.io/hyperledger, docker.io/library, ghcr.io/hyperledger); any other image there needs a decision and a pull secret.

  python3 -m unittest discover -s multiorg
"""
import os, re, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PRIVATE = ("fsc", "gw", "ceremony")
PUBLIC_ONLY = ("arma", "committer", "fca")
PUBLIC_PREFIX = ("docker.io/hyperledger/", "docker.io/library/", "ghcr.io/hyperledger/")


def src(mod):
    return open(os.path.join(HERE, mod, "render.py")).read()


class PullSecrets(unittest.TestCase):
    def test_private_image_renders_set_the_pull_secret(self):
        for mod in PRIVATE:
            self.assertRegex(src(mod), r'"imagePullSecrets":\s*\[\{"name":\s*"ghcr-pull"\}\]', mod)

    def test_upstream_renders_name_public_images_only(self):
        for mod in PUBLIC_ONLY:
            imgs = re.findall(r'"((?:docker\.io|ghcr\.io|quay\.io|registry[\w.-]*|[\w.-]+\.(?:com|io|cn))/[\w./-]+@sha256:[0-9a-f]{64})"', src(mod))
            self.assertTrue(imgs, mod)
            for i in imgs:
                self.assertTrue(i.startswith(PUBLIC_PREFIX), f"{mod}: {i} is not a public upstream image: it needs imagePullSecrets and a decision")

    def test_no_render_names_a_private_package_of_ours_without_the_secret(self):
        for mod in PUBLIC_ONLY:
            self.assertNotIn("radityaaa43", src(mod), mod)


if __name__ == "__main__":
    unittest.main()
