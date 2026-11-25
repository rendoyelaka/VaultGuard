import sys
import xml.etree.ElementTree as ET

ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
ET.register_namespace('tools', 'http://schemas.android.com/tools')
ET.register_namespace('', '')

path = "app/src/main/AndroidManifest.xml"

# Parse preserving namespaces
tree = ET.parse(path)
root = tree.getroot()

ns = {'android': 'http://schemas.android.com/apk/res/android'}

app_elem = root.find('application')
if app_elem is None:
    print("ERROR: <application> element not found")
    sys.exit(1)

# Find and remove the DexInitProvider <provider> element
to_remove = None
for child in list(app_elem):
    name_attr = child.get('{http://schemas.android.com/apk/res/android}name', '')
    if 'DexInitProvider' in name_attr:
        to_remove = child
        break

if to_remove is not None:
    app_elem.remove(to_remove)
    print("DexInitProvider provider element removed OK")
else:
    print("DexInitProvider not found — already absent or never present")

tree.write(path, xml_declaration=True, encoding='utf-8')

# Verify XML is valid after write
try:
    ET.parse(path)
    print("XML valid after patch")
except ET.ParseError as e:
    print(f"ERROR: XML invalid after patch: {e}")
    sys.exit(1)
