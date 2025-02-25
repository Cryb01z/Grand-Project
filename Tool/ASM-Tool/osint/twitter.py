import asyncio
from twikit import Client

USERNAME = ''
EMAIL = ''
PASSWORD = ''

client = Client(
    language='en-US'
)

async def main(tweet_query):
    await client.login(
        auth_info_1=USERNAME,
        auth_info_2=EMAIL,
        password=PASSWORD
    )
    client.save_cookies("cookies.json")
    tweets = await client.search_tweet(tweet_query, 'top', count=10)
    tweet_data = [
        {
            "user_name": single_tweet.user.name,
            "profile_image_url": single_tweet.user.profile_image_url,
            "text": single_tweet.text
        }
        for single_tweet in tweets
    ]
    return tweet_data
  
asyncio.run(main('lmao'))

