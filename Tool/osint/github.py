import httpx

GITHUB_API_KEY = ""


async def perform_github_dorking(query):
    url = f"https://api.github.com/search/code?q={query}"
    headers = {
        "Authorization": f"token {GITHUB_API_KEY}",
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return [item["html_url"] for item in data.get("items", [])]
        else:
            print(f"Error in GitHub Dorking: {response.text}")
            return []
    except Exception as e:
        print(f"Error in GitHub Dorking: {e}")
        return []


# def main():
#     github_dork = 'lmaolmaolmao@gmail.com'
#     print(f"Running GitHub Dork: {github_dork}")
#     github_results = github_dorking(github_dork)
#     print("GitHub Dork Results:")
#     for link in github_results:
#         print(f" - {link}")

# if __name__ == "__main__":
#     main()