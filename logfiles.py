import os
import xml.etree.ElementTree as ET
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

xml_file_path = r"C:\Users\Jing-Ting\Downloads\SecurityLog-rev2.xml"

if not os.path.exists(xml_file_path):
    print(f"File not found: {xml_file_path}")
    exit(1)

tree = ET.parse(xml_file_path)
root = tree.getroot()
url = root[0].tag[:-len("Event")]
event_data_list = []

for event in root:
    output = {}

    # Parsing EventData
    eventData = event.find(url + "EventData")
    if eventData is not None:
        for data in eventData:
            name = data.attrib.get('Name')
            output[name] = data.text if data.text else ""

    # Parsing Stuff
    system = event.find(url + "System")
    if system is not None:
        event_id_el = system.find(url + "EventID")
        if event_id_el is not None:
            output["EventID"] = event_id_el.text

        time_created_el = system.find(url + "TimeCreated")
        if time_created_el is not None:
            time_str = time_created_el.attrib.get("SystemTime", "")
            output["SystemTime"] = time_str
            if time_str:
                try:
                    t_str = time_str.rstrip("Z")
                    dt = datetime.fromisoformat(t_str)
                    time_period = dt.strftime("%Y-%m-%d %H:00")
                except Exception:
                    time_period = time_str
                output["TimePeriod"] = time_period

        computer_el = system.find(url + "Computer")
        if computer_el is not None:
            output["TargetServerName"] = computer_el.text

    if "WorkstationName" in output and "WorkStation" not in output:
        output["WorkStation"] = output["WorkstationName"]

    event_data_list.append(output)

df_events = pd.DataFrame(event_data_list)
df_events["TimePeriod_dt"] = pd.to_datetime(df_events["TimePeriod"], format="%Y-%m-%d %H:%M", errors="coerce")
df_events["Hour"] = df_events["TimePeriod_dt"].dt.hour

tail_fields = ["TargetDomainName", "TargetInfo", "LogonProcessName", "IpAddress", "TargetServerName", "WorkStation", "TargetLogonId"]

def make_details(row):
    parts = []
    for field in tail_fields:  # Updated: using tail_fields instead of undefined detail_fields
        val = row.get(field, "")
        if pd.notna(val) and val != "":
            parts.append(f"{field}: {val}")
    return "; ".join(parts)

df_events["Details"] = df_events.apply(make_details, axis=1)
df_logons = df_events[df_events["EventID"] == "4624"].copy()
user_frequency = df_logons["TargetUserName"].value_counts().to_dict()
time_frequency = df_logons["Hour"].value_counts().to_dict()
df_events.loc[df_events["EventID"] == "4624", "UserFrequency"] = df_events.loc[df_events["EventID"] == "4624", "TargetUserName"].map(user_frequency)
df_events.loc[df_events["EventID"] == "4624", "TimeFrequency"] = df_events.loc[df_events["EventID"] == "4624", "Hour"].map(time_frequency)
df_plot = df_logons.groupby(["Hour", "TargetUserName"]).size().unstack(fill_value=0)

# After reading the excel sheet, I found that DC01$, EX01$, and DC2$ have the highest frequency for
# computers while the other 3 have the highest frequency for normal users
desired_users = ["DC01$", "EX01$", "DC2$", "grant.larson", "Matt.Edwards", "randal.graves"]
df_plot = df_plot.reindex(columns=desired_users, fill_value=0)

combined_csv_path = r"C:\Users\Jing-Ting\Downloads\Windows_Security_Log_Analysis.csv"
with open(combined_csv_path, 'w', newline='', encoding='utf-8') as f:
    f.write("Detailed Event Data\n")
    df_events.to_csv(f, index=False)
    f.write("\n\n")
    f.write("Logon Frequency (Pivot Table) for Selected Users\n")
    df_plot.to_csv(f)
print(f"Combined CSV file saved to {combined_csv_path}")

plt.figure(figsize=(12, 6))
ax = df_plot.plot(kind="bar", figsize=(12, 6))
ax.set_xlabel("Time (Hour)")
ax.set_ylabel("Frequency")
ax.set_title("Frequency of High Logon Rate Users")
plt.legend(title="Users", bbox_to_anchor=(1.0, 1.0))
plt.tight_layout()

chart_path = r"C:\Users\Jing-Ting\Downloads\logon_frequency_chart.png"
plt.savefig(chart_path)
print(f"Chart saved to {chart_path}")
plt.show()
