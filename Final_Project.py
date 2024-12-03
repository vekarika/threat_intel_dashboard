import tweepy
import streamlit as st
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os
import pandas as pd
import nltk
from textblob import TextBlob
import matplotlib.pyplot as plt
from nltk.sentiment.vader import SentimentIntensityAnalyzer

# Ensure that necessary NLTK data is downloaded
nltk.download('vader_lexicon')

# Set up l/Applications/Python\ 3.x/Install\ Certificates.commandogging for error details
logging.basicConfig(filename='error_log.txt', level=logging.DEBUG)

# Streamlit UI - Abigail Threat Intelligence Dashboard
st.title("ABIGAIL THREAT INTELLIGENCE DASHBOARD")

# Add 3MTT October Knowledge Showcase info followed by Analyst Information in capital letters
st.sidebar.markdown(
    """
    <div style="font-weight: bold; color: #003366; font-size: 18px;">
        <span style="color: green;">3MTT OCTOBER KNOWLEDGE SHOWCASE</span>: THREAT INTELLIGENCE DASHBOARD<br><br>
        <div style="font-size: 16px; font-weight: bold; text-transform: uppercase;">ANALYST INFORMATION</div><br>
        NAME: ABIGAIL JOSEPH<br>
        ID: FE/23/45687108<br>
        TRACK: CYBERSECURITY COHORT 2
    </div>
    """, unsafe_allow_html=True)

# Initialize the SentimentIntensityAnalyzer
sia = SentimentIntensityAnalyzer()

# Function to fetch tweets with retry mechanism
def fetch_tweets(keywords, bearer_token, retry_count=5):
    # Initialize Tweepy client with Bearer Token
    client = tweepy.Client(bearer_token=bearer_token)

    # Attempt to fetch tweets with retries on failure
    attempt = 0
    tweet_list = []
    while attempt < retry_count:
        try:
            # Define your search query
            query = " OR ".join(keywords) + " -is:retweet"
            # Fetch tweets
            tweets = client.search_recent_tweets(query=query, tweet_fields=["public_metrics", "created_at"],
                                                 max_results=10)  # Set max_results to 10 or higher

            # Check if there are tweets
            if tweets.data:
                st.write("Tweets fetched successfully!")
                for tweet in tweets.data:
                    tweet_dict = {
                        "Tweet ID": tweet.id,
                        "Text": tweet.text,
                        "Likes": tweet.public_metrics['like_count'],
                        "Retweets": tweet.public_metrics['retweet_count'],
                        "Tweet Date": tweet.created_at
                    }
                    tweet_list.append(tweet_dict)

                return tweet_list  # Return the fetched tweets
            else:
                st.write("No tweets found.")
                return None

        except tweepy.TweepyException as e:
            if attempt < retry_count - 1:
                backoff_time = 2 ** attempt  # Exponential backoff time: 1, 2, 4, 8, etc.
                st.warning(f"Error fetching tweets: {e}. Retrying in {backoff_time} seconds...")
                logging.error(f"Error on attempt {attempt + 1}: {e}")
                time.sleep(backoff_time)  # Wait before retrying
            else:
                st.error(f"Error fetching tweets: {e}. No more retries.")
                logging.error(f"Final error after all retries: {e}")
                break

        attempt += 1


# Function to send email alert
def send_email_alert(sender_email, recipient_email, tweet):
    try:
        # Email server setup (using Gmail as an example)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()

        # Login to the sender's email account
        app_password = os.getenv('nvbltvekfqlupokv')  # Fetch App Password from environment variable
        if app_password is None:
            st.error("Email App Password is missing. Set the environment variable.")
            return
        server.login(sender_email, app_password)  # Use App Password

        # Create the email message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = 'Critical Keyword Alert - Threat Intelligence'

        # Add body to the email
        body = f"""
        A tweet containing a critical keyword has been found:

        Tweet ID: {tweet.id}
        Tweet Date: {tweet.created_at}
        Tweet Text: {tweet.text}
        """
        message.attach(MIMEText(body, 'plain'))

        # Send the email
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()

        st.write("Email alert sent successfully!")

    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")
        st.error(f"Error sending email: {e}")


# Streamlit UI for entering keywords
keywords_input = st.text_input("Enter Keywords (comma separated)", "cybersecurity, data breach, insider threat")
keywords = [keyword.strip() for keyword in keywords_input.split(",")]

# Streamlit UI for Critical Keywords - Separate section for Email Alerts
st.subheader("Critical Keywords for Email Alerts")
critical_keywords_input = st.text_input("Enter Critical Keywords for Alerts (comma separated)",
                                        "hacked, attack, breach")
critical_keywords = [keyword.strip() for keyword in critical_keywords_input.split(",")]

# Enter Bearer Token
bearer_token = st.text_input("Enter Bearer Token", type="password")

# Email inputs (use default input type)
st.subheader("Email Alerts (Optional)")
sender_email = st.text_input("Sender Email")
recipient_email = st.text_input("Recipient Email")

# Check if bearer_token is provided before attempting to fetch tweets
tweet_data = []  # Initialize tweet_data as an empty list to avoid 'not defined' errors

if bearer_token:
    st.write(f"Filtering tweets for the following keywords: {keywords}")

    # Fetch tweets and send email if critical keyword is detected
    tweet_data = fetch_tweets(keywords, bearer_token)

    # Handle errors if the bearer token is missing
    if not tweet_data:
        st.warning("No tweets fetched or error occurred.")
else:
    st.warning("Bearer Token is missing!")

# Sentiment Breakdown
if tweet_data:  # Ensure tweet_data exists
    st.subheader("Sentiment Breakdown")

    # Function to analyze sentiment using VADER
    def analyze_sentiment(text):
        # Get the sentiment scores from VADER
        sentiment = sia.polarity_scores(text)

        # Return the sentiment as positive, neutral, or negative based on compound score
        if sentiment['compound'] >= 0.05:
            return 'Positive'
        elif sentiment['compound'] <= -0.05:
            return 'Negative'
        else:
            return 'Neutral'


    sentiments = [analyze_sentiment(tweet['Text']) for tweet in tweet_data]
    sentiment_count = pd.Series(sentiments).value_counts()

    # Plotting the sentiment breakdown
    sentiment_count.plot(kind='pie', autopct='%1.1f%%', startangle=90, colors=['#ff9999', '#66b3ff', '#99ff99'])
    plt.title("Sentiment Breakdown")
    st.pyplot(plt)

# CSV Export
if tweet_data:  # Ensure tweet_data exists
    st.subheader("Export Filtered Tweets to CSV")
    df = pd.DataFrame(tweet_data)
    st.dataframe(df)

    # Button to download CSV
    csv = df.to_csv(index=False)
    st.download_button("Download CSV", csv, file_name="filtered_tweets.csv", mime="text/csv")

# Streamlit UI for TextBlob Sentiment Analysis
st.subheader("Sentiment Analysis with TextBlob")
text_input = st.text_area("Enter text for analysis", "I love using Streamlit and TextBlob!")

# Perform sentiment analysis with TextBlob
blob = TextBlob(text_input)
st.write(f"Sentiment: {blob.sentiment}")
