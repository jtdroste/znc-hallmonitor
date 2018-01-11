'''
hallmonitor - ZNC Python Module that monitors for a keyword, and publish to a SNS topic when detected
'''
import base64
import hashlib
import hmac
import json
import urllib.parse, urllib.request
import znc
import sys
from time import strftime, gmtime, time

class hallmonitor(znc.Module):
    description = "ZNC Monitor for messages"

    def OnLoad(self, args, retmsg):
        self.NV_VERSION = "1.0.0"

        self.loaded_nv = {}
        
        self.config_values = {
            'monitor_channels': {
                'type': 'list',
                'desc': 'A comma-separated list of channels to notify in. Include the #. Must be lowercased.',
                'default': [],
            },
            'trigger_pms': {
                'type': 'bool',
                'desc': 'Trigger notifications on PMs. Use "on" or "off".',
                'default': True,
            },
            'trigger_words': {
                'type': 'list',
                'desc': 'A comma-separated list of words to notify on. Must be lowercased.',
                'default': [],
            },
            'endpoint': {
                'type': 'str',
                'desc': 'Endpoint to use when communicating with SNS. Only the subdomain.',
                'default': 'sns.us-east-1.amazonaws.com',
            },
            'sns_topic': {
                'type': 'str',
                'desc': 'SNS Topic to send notifications to.',
                'default': '',
            },
            'aws_access_key': {
                'type': 'str',
                'desc': 'AWS Access Key.',
                'default': '',
            },
            'aws_secret_key': {
                'type': 'str',
                'desc': 'AWS Secret Key.',
                'default': '',
            },
            'always_send_notifications': {
                'type': 'bool',
                'desc': 'Always send notifications, regardless of client status. Use "on" or "off".',
                'default': False,
            },
            'auto_notifications_on_dc': {
                'type': 'bool',
                'desc': 'Automatically enable notifications when a client disconnects. Use "on" of "off".',
                'default': False,
            },
        }

        # Fill in the defaults
        force_write = False
        if 'nv_version' not in self.nv or self.nv['nv_version'] != self.NV_VERSION:
            self.nv['nv_version'] = self.NV_VERSION
            force_write = True

        for key, cfg in self.config_values.items():
            if key not in self.nv or force_write:
                self.nv[key] = json.dumps(cfg['default'])

        # Load from NV
        self._load_from_nv()

        return True

    def OnModCommand(self, message):
        msg = message.split()
        key = msg[0]

        # Help or unknown
        if key not in self.config_values or key == "help":
            if key != "help":
                self.PutModule('Unknown command option "{}".'.format(key))

            self.PutModule("Usage: config-key [config value]. If you do not give a value, I will return the current value.")
            self.PutModule("The following config keys are available:")

            for k, cfg in self.config_values.items():
                self.PutModule("- {}: {}".format(k, cfg['desc']))
                self.PutModule("-- Value: {}".format(self.nv[k]))

            return znc.CONTINUE

        key = msg[0]
        item = self.config_values[key]

        # We're getting the value
        if len(msg) == 1:
            self.PutModule("{}: {}".format(key, self.nv[key]))
            return znc.CONTINUE

        # We're setting
        if item['type'] == 'list':
            val = ' '.join(msg[1:]).split(',')
        elif item['type'] == 'bool':
            val = True if msg[1].lower() == 'on' else False
        else:
            val = msg[1]

        self._set_nv(key, val)
        self.PutModule("{} has been set to: {}".format(key, self.nv[key]))

    def OnClientDisconnect(self):
        if self.loaded_nv['auto_notifications_on_dc']:
            self._notify('HallMonitor', 'Detected client disconnect. Enabling notifications.', force=True)

    def OnPrivMsg(self, nick, message):
        if self.loaded_nv['trigger_pms']:
            self._notify('{}@'.format(nick), message)

        return znc.CONTINUE

    def OnChanMsg(self, nick, channel, message):
        if channel.lower() not in self.loaded_nv['monitor_channels']:
            return znc.CONTINUE

        triggered = False
        msg = str(message)
        for trigger in self.loaded_nv['trigger_words']:
            if trigger.lower() in msg.lower():
                triggered = True
                break

        if triggered:
            who = "{} ({}@)".format(channel, nick)
            self._notify(who, message)

        return znc.CONTINUE

    def _set_nv(self, key, value):
        self.nv[key] = json.dumps(value)
        self.loaded_nv[key] = value

    def _load_from_nv(self):
        # Load from the storage
        for key, _ in self.config_values.items():
            self.loaded_nv[key] = json.loads(self.nv[key])

    def _notify(self, who, message, force=False):
        notify = self.loaded_nv['always_send_notifications']
        if self.loaded_nv['auto_notifications_on_dc'] and not self.GetUser().IsUserAttached():
            notify = True

        if not notify and not force:
            return

        if len(self.loaded_nv['aws_access_key']) == 0 or \
                len(self.loaded_nv['aws_secret_key']) == 0 or \
                len(self.loaded_nv['sns_topic']) == 0:
            return

        msg = '{} - {}'.format(who, message)

        params = {
            'TopicArn': self.loaded_nv['sns_topic'],
            'Message': msg,
            'Timestamp': strftime("%Y-%m-%dT%H:%M:%S.000Z", gmtime(time())),
            'AWSAccessKeyId': self.loaded_nv['aws_access_key'],
            'Action': 'Publish',
            'SignatureVersion': '2',
            'SignatureMethod': 'HmacSHA256',
        }

        # Sort the params, and build it
        params_keys = sorted(params.keys())
        params_values = map(params.get, params_keys)

        # We do this because we're running on 3.4, which doesn't
        # let us use quote instead of quoete for urllib.parse.urlencode
        params_http = ""
        for k, v in list(zip(params_keys, params_values)):
            params_http += "{}={}&".format(urllib.parse.quote(k, safe=''), urllib.parse.quote(v, safe=''))
        params_http = params_http[:-1]

        string_to_sign = '\n'.join(['GET', self.loaded_nv['endpoint'], '/', params_http])
        signature = base64.b64encode(hmac.new(
            key=bytes(self.loaded_nv['aws_secret_key'], 'ascii'),
            msg=bytes(string_to_sign, 'ascii'),
            digestmod=hashlib.sha256).digest()).decode('utf-8').strip()

        url = 'http://{}/?{}&Signature={}'.format(self.loaded_nv['endpoint'], params_http, urllib.parse.quote_plus(signature))

        try:
            res = urllib.request.urlopen(url).read()
        except Exception as e:
            self.PutModule('[DEBUG] URL: {}'.format(url))
            self.PutModule('[DEBUG] Exception: {}'.format(e))
            pass

