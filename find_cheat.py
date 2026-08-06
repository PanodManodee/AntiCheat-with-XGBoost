import pandas as pd
import os
import glob

files = glob.glob("Session_4/Match_2/Server/*.csv")
for file in files:
    df = pd.read_csv(file)
    df = df[df["event_type"] == "cheat"]
    df.to_csv("output.csv")
