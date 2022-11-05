from features import FeatureExtraction
from flask import send_from_directory, url_for
from html2image import Html2Image
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
import numpy as np
import validators
import pickle
import time
import re
import os


screenshot_dir = 'screenshot/'

h2i = Html2Image()
h2i.output_path = screenshot_dir


stats_filename = 'stats.txt'
model = pickle.load(open("model.pkl", "rb"))


def format_url(url):
    if not re.match('(?:http|ftp|https)://', url):
        return 'http://{}'.format(url)
    return url


def capture_screenshot(target_url, filename='screenshot.png', size=(1920, 1080)):
    h2i.screenshot(url=target_url, save_as=filename, size=size)
    return send_from_directory(screenshot_dir, path=filename)


def get_phishing_result(target_url, config=None):
    target_url = format_url(target_url)
    if not (target_url and validators.url(target_url)):
        return dict(status=False, message="You have provided an invalid target url, Please try again after updating the url.")

    try:
        update_stats('checked')
        target = urlparse(target_url)
        
        ssHeight = None
        ssWidth = None

        if "screenshot" in config:
            ssHeight = config["screenshot"]["height"]
            ssWidth = config["screenshot"]["width"]

        screenshot_uri = url_for('screenshot', target=target_url, height=ssHeight, width=ssWidth)
        # features_obj = FeatureExtraction(target_url)
        # x = np.array(features_obj.getFeaturesList()).reshape(1, 30)
        # y_pred = model.predict(x)[0]  # 1 is safe -1 is not
        # y_pro_phishing = model.predict_proba(x)[0, 0]
        # y_pro_non_phishing = model.predict_proba(x)[0, 1]
        # pred = "It is {0:.2f}% safe to go ".format(y_pro_phishing*100)
        # xx = round(y_pro_non_phishing, 2)

        return dict(
            status=True,
            domain=target.netloc,
            target=target_url,
            screenshot=screenshot_uri,
            # features_obj=features_obj,
            # x=x,
            # y_pred=y_pred,
            # y_pro_phishing=y_pro_phishing,
            # y_pro_non_phishing=y_pro_non_phishing,
            # pred=pred,
            # xx=xx
        )
    except Exception as e:
        return dict(status=False, message=str(e))


def get_stats(key=None):
    stats = {}
    if os.path.exists(stats_filename):
        with open(stats_filename, "r") as file:
            for line in file:
                (k, v) = line.split(":")
                stats[k] = int(v)

        if key is not None:
            return stats[key] if key in stats else None

        return stats

    return False


def update_stats(key):
    stats = get_stats()
    with open("stats.txt", "w+") as file:
        if stats is False:
            file.write('visits:0\nchecked:0\nphished:0')
        else:
            lines = []
            for k, v in stats.items():
                if k == key:
                    v += 1
                lines.append(f"{k}:{v}")
            file.write("\n".join(lines))
        file.flush()
