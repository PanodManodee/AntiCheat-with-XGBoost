import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import glob

interval = "100ms"

files = glob.glob("Session_1/Match_1/Clients/*.csv")
for file in files:
    df = pd.read_csv(file)
    df["ts"] = pd.to_datetime(df["ts"], format="ISO8601")
    df = df.sort_values("ts")
    packets_per_time = df.resample(interval, on="ts").size()
    plt.plot(
        packets_per_time.index, packets_per_time.values, label=os.path.basename(file)
    )


plt.xlabel("Time")
plt.ylabel("Packets/" + interval)
plt.title("Outgoing traffic comparison")
plt.tight_layout()
plt.legend(loc="upper left", bbox_to_anchor=(1, 1))
plt.grid()
plt.xticks(rotation=45)
plt.savefig("plot.png", dpi=500, bbox_inches="tight")
plt.show()
