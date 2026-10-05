"""Inspect shipped assets/XML/dependency groups, optionally checking a packed consumer's restore."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("package", type=Path)
parser.add_argument("--assets", type=Path)
args = parser.parse_args()
versions = {"net8.0": "8.0.31", "net9.0": "9.0.20", "net10.0": "10.0.12"}
with zipfile.ZipFile(args.package) as package:
    names = package.namelist()
    assert "README.md" in names
    assert {name for name in names if name.startswith("lib/")} == {
        f"lib/{tfm}/Umtb.Platform.Security.{extension}"
        for tfm in versions for extension in ("dll", "xml")
    }, "Unexpected library assets"
    assert not any(name.startswith(("src/", "tests/", "samples/", "docs/", "keycloak/", "scripts/"))
                   or name.endswith((".cs", ".csproj", ".slnx", ".props", ".config", ".yaml", ".py"))
                   for name in names), "Development-only content must not ship in the package"
    for tfm in versions:
        assert f"lib/{tfm}/Umtb.Platform.Security.dll" in names
        xml = ET.fromstring(package.read(f"lib/{tfm}/Umtb.Platform.Security.xml"))
        members = xml.findall("./members/member")
        assert len(members) >= 30
        assert all(member.find("summary") is not None for member in members)
    nuspec = ET.fromstring(package.read(next(name for name in names if name.endswith(".nuspec"))))
    ns = {"n": nuspec.tag.split("}")[0][1:]}
    assert nuspec.findtext("n:metadata/n:id", namespaces=ns) == "Umtb.Platform.Security"
    assert nuspec.findtext("n:metadata/n:version", namespaces=ns) == "0.1.0-preview.1"
    groups = nuspec.findall(".//n:dependencies/n:group", ns)
    assert {group.attrib["targetFramework"] for group in groups} == set(versions)
    for group in groups:
        dependencies = {d.attrib["id"]: d.attrib["version"] for d in group}
        assert set(dependencies) == {"Microsoft.AspNetCore.Authentication.JwtBearer", "Microsoft.IdentityModel.Protocols.OpenIdConnect"}
        assert dependencies["Microsoft.AspNetCore.Authentication.JwtBearer"] == versions[group.attrib["targetFramework"]]
        assert dependencies["Microsoft.IdentityModel.Protocols.OpenIdConnect"] == "8.23.0"
    frameworks = nuspec.findall(".//n:frameworkReference", ns)
    assert len(frameworks) == 3 and all(f.attrib["name"] == "Microsoft.AspNetCore.App" for f in frameworks)

if args.assets:
    assets = json.loads(args.assets.read_text(encoding="utf-8"))
    for tfm, version in versions.items():
        target = assets["targets"][tfm]
        entry = target["Umtb.Platform.Security/0.1.0-preview.1"]
        assert entry["type"] == "package", "Consumer is using a project reference instead of the nupkg"
        assert f"lib/{tfm}/Umtb.Platform.Security.dll" in entry["compile"]
        assert f"Microsoft.AspNetCore.Authentication.JwtBearer/{version}" in target
        assert "Microsoft.IdentityModel.Tokens/8.23.0" in target
        relative = assets["libraries"]["Umtb.Platform.Security/0.1.0-preview.1"]["path"]
        restored = next((Path(folder) / relative for folder in assets["packageFolders"]
                         if (Path(folder) / relative).is_dir()), None)
        assert restored is not None, "Restored package directory not found"
        with zipfile.ZipFile(args.package) as package:
            asset_path = f"lib/{tfm}/Umtb.Platform.Security.dll"
            assert (restored / asset_path).read_bytes() == package.read(asset_path), "Consumer cache contains a different build"
print("NuGet assets, XML documentation, framework references, and dependency selection verified")
