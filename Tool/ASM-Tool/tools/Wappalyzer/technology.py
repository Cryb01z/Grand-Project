import re
import chardet



def detect_encoding(filename):
    """
    Detect encoding of a file.
    Args:
        filename (str): The path to the file to read.
    Returns:
        str: The encoding of the file.
    """
    with open(filename, 'rb') as f:
        raw_data = f.read()
    result = chardet.detect(raw_data)
    return result['encoding']


def filter_technology(filename, pattern: str):
    """
    Filter technology from file based on pattern.
    
    Args:
        filename (str): The path to the file to read.
        pattern (str): The regex pattern to search for.

    Returns:
        list: List of lines matching the pattern.
    """
    encoding = detect_encoding(filename)
    with open(filename, 'r', encoding=encoding) as f:
        data = [i for i in f.readlines() if re.search(pattern, i)]
    return list(set(data))



def extract_plugin_version(url, plugin_pattern, version_pattern):
    """
    Extract plugin name and version from url (typically for wordpress :D)
    Args:
        url: link to use
        plugin_pattern: pattern to extract plugin name
        version_pattern: pattern to extract version
    Returns:
        version and plugin name of plugin was used
    """

    plugin = re.search(plugin_pattern, url)
    version = re.search(version_pattern, url)

    return plugin.group(0) if plugin else None, version.group(0) if version else None

#this use for testing the function
# def main():
#     plugins = dict()
#     try:
#         data = filter_technology('test2.txt', 'wp-content')
#         for url in data:
#             plugin, version = extract_plugin_version(url, r"(?<=plugins/)[^/]*", version_pattern=r"(?<=ver=)[^&]*")
#             plugins.update({plugin: version})

#         data = filter_technology('test2.txt', 'wp-includes')
#         for url in data:
#             plugin, version = extract_plugin_version(url,plugin_pattern=r"(?<=/)[^/]*?(?=\?ver=)", version_pattern=r"(?<=ver=)[^&]*")
#             plugins.update({plugin: version})

#         for key, values in plugins.items():
#             print(key, values)
#     except Exception as e:
#         print(e)


# if __name__ == '__main__':
#     main()