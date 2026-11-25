import re, sys

path = "app/src/main/AndroidManifest.xml"
txt = open(path).read()

# Remove the <provider> block containing DexInitProvider
cleaned = re.sub(r'\s*<provider[^>]*\.DexInitProvider[\s\S]*?/>', '', txt)

# Also remove the comment block about DexInitProvider
cleaned = re.sub(r'\s*<!--[\s\S]*?DexInitProvider[\s\S]*?-->', '', cleaned)

open(path, 'w').write(cleaned)

# Check only for XML tag — not comments
if re.search(r'<provider[^>]*DexInitProvider', cleaned):
    print("ERROR: DexInitProvider provider tag still present")
    sys.exit(1)

print("DexInitProvider removed OK")
