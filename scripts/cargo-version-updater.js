const VERSION_REGEXP = /^version\s*=\s*"([^"]+)"/m;

const readVersion = function (contents) {
    const matches = contents.match(VERSION_REGEXP);
    if (!matches) {
        throw new Error("Version key not found!");
    }
    return matches[1];
}

const writeVersion = function (contents, version) {
    return contents.replace(VERSION_REGEXP, `version = "${version}"`);
}

module.exports = {readVersion, writeVersion};
