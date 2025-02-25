import requests
import json

# constant
GITHUB_API = "https://api.github.com/repos/"

current_sha_tech = "1ccde2679a50813c9c1765c8168d9f9552ebc45a"
# current_sha = "e7355e9b357dc4e70ca68b649efebbfe6d4738ac"
current_sha_category = ""


def check_update(repo_name: str, file_name: str) -> str:
    """
    Check the latest commit SHA for the given repository path.

    Parameters:
    repo_name (str): The repo name to check.
    file_name (str): The file name to check.

    Returns:
    str: The latest commit SHA.
    """
    try:
        response = requests.get(f"{GITHUB_API}{repo_name}/commits?path={file_name}")
        response.raise_for_status()
        latest_commit_sha = response.json()[0]['sha']
        return latest_commit_sha
    except requests.RequestException as e:
        print(f"Failed to fetch the latest commit SHA for {file_name} due to: {e}")
        return None


def get_latest_data(repo_name: str, file_name: str, current_sha: str) -> dict:
    """
    Get the latest data from the repository.

    Parameters:
    repo_path (str): The path within the repository to check.
    file (str): The file to fetch.

    Returns:
    dict: The latest data.
    """
    try:
        if check_update(repo_name, file_name) != current_sha:
            response = requests.get(f"https://raw.githubusercontent.com/{repo_name}/main/{file_name}")
            response.raise_for_status()
            data = response.json()
            return data
    except requests.RequestException as e:
        print(f"Failed to fetch the latest data for {file_name} due to: {e}")
        return None


def get_latest_wapp_technologies():
    """
    Get the latest Wappalyzer technology data, replacing the key 'apps' with 'technologies'.

    Parameters:
    current_sha (str): The current SHA of the file to compare with.
    """
    repo_name = "projectdiscovery/wappalyzergo"
    file_name = "fingerprints_data.json"
    latest_data = get_latest_data(repo_name, file_name, current_sha_tech)

    if latest_data:
        json_str = json.dumps(latest_data)
        json_str_replace = json_str.replace("\"apps\"", "\"technologies\"").replace("\"scriptSrc\"", "\"scripts\"")
        modified_data = json.loads(json_str_replace)
        return modified_data
    else:
        print("Data is already up-to-date or failed to fetch.")


def get_latest_wapp_categories():
    """
    Get the latest Wappalyzer category data, replacing the key 'categories' with 'categories'.

    Parameters:
    current_sha (str): The current SHA of the file to compare with.
    """
    try:
        repo_name = "projectdiscovery/wappalyzergo"
        file_name = "categories_data.json"
        latest_data = get_latest_data(repo_name, file_name, current_sha_category)

        if latest_data:
            json_str = json.dumps(latest_data)
            modified_data = json.loads(json_str)
            return {"categories": modified_data}
        else:
            print("Data is already up-to-date or failed to fetch.")
    except Exception as e:
        print(f"Failed to fetch the latest data for {file_name} due to: {e}")
        return None


def get_updated_data() :
    """
    Get the updated data from the repositories.

    Parameters:
    current_sha (str): The current SHA of the file to compare with.
    """
    technology = get_latest_wapp_technologies()
    category = get_latest_wapp_categories()
    new_json = {**technology, **category}
    return new_json

#use to test the function   
# def main():
#     print(get_updated_data())


# if __name__ == '__main__':
#     main()
