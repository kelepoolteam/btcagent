/*
 Mining Pool Agent

 Copyright (C) 2016  BTC.COM

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "Utils.h"

#include <stdarg.h>

#include <algorithm>
#include <iostream>
#include <iomanip>

#if defined(SUPPORT_GLOG) && defined(GLOG_TO_STDOUT)
void GLogToStdout::send(google::LogSeverity severity, const char* full_filename,
    const char* base_filename, int line, const struct ::tm* tm_time,
    const char* message, size_t message_len) {

    std::cout << ToString(severity, base_filename, line, tm_time, message, message_len) << std::endl;
}

std::string GLogToStdout::ToString(google::LogSeverity severity, const char* file, int line,
    const struct ::tm* tm_time, const char* message, size_t message_len) {

    std::ostringstream stream;

    stream << '[' << 1900 + tm_time->tm_year << '-'
        << std::setfill('0')
        << std::setw(2) << 1 + tm_time->tm_mon << '-'
        << std::setw(2) << tm_time->tm_mday << ' '
        << std::setw(2) << tm_time->tm_hour << ':'
        << std::setw(2) << tm_time->tm_min << ':'
        << std::setw(2) << tm_time->tm_sec << "] ";

    stream << string(message, message_len);

    return stream.str();
}
#endif

string Strings::Format(const char * fmt, ...) {
  char tmp[512];
  string dest;
  va_list al;
  va_start(al, fmt);
  int len = vsnprintf(tmp, 512, fmt, al);
  va_end(al);
  if (len>511) {
    char * destbuff = new char[len+1];
    va_start(al, fmt);
    len = vsnprintf(destbuff, len+1, fmt, al);
    va_end(al);
    dest.append(destbuff, len);
    delete[] destbuff;
  } else {
    dest.append(tmp, len);
  }
  return dest;
}

void Strings::Append(string & dest, const char * fmt, ...) {
  char tmp[512];
  va_list al;
  va_start(al, fmt);
  int len = vsnprintf(tmp, 512, fmt, al);
  va_end(al);
  if (len>511) {
    char * destbuff = new char[len+1];
    va_start(al, fmt);
    len = vsnprintf(destbuff, len+1, fmt, al);
    va_end(al);
    dest.append(destbuff, len);
    delete[] destbuff;
  } else {
    dest.append(tmp, len);
  }
}

string getJsonStr(const char *c,const jsmntok_t *t) {
  if (t == NULL || t->end <= t->start)
    return "";

  return string(c + t->start, t->end - t->start);
}

static
int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

bool parseConfJson(const string &jsonStr,
                   string &agentType, string &listenIP, string &listenPort,
                   std::vector<PoolConf> &poolConfs,
                   bool &alwaysKeepDownconn, bool &disconnectWhenLostAsicBoost,
                   bool &useIpAsWorkerName, bool &submitResponseFromServer,
                   string &fixedWorkerName,bool &encrypting) {
  jsmn_parser p;
  jsmn_init(&p);
  jsmntok_t t[64]; // we expect no more than 64 tokens
  int r;
  const char *c = jsonStr.c_str();

  // pase json string
  r = jsmn_parse(&p, jsonStr.c_str(), jsonStr.length(), t, sizeof(t)/sizeof(t[0]));

  // assume the top-level element is an object
  if (r < 1 || t[0].type != JSMN_OBJECT) {
    LOG(ERROR) << "json decode failure" << std::endl;
    return false;
  }

  for (int i = 1; i < r; i++) {
    if (jsoneq(c, &t[i], "agent_type") == 0) {
      agentType = getJsonStr(c, &t[i+1]);
      i++;
    }
    if (jsoneq(c, &t[i], "agent_listen_ip") == 0) {
      listenIP = getJsonStr(c, &t[i+1]);
      i++;
    }
    else if (jsoneq(c, &t[i], "agent_listen_port") == 0) {
      listenPort = getJsonStr(c, &t[i+1]);
      i++;
    }
    else if (jsoneq(c, &t[i], "pools") == 0) {
      //
      // "pools": [
      //    ["cn.ss.btc.com", 1800, "kevin1"],
      //    ["cn.ss.btc.com", 1800, "kevin2"],
      // ]
      //
      i++;
      if (t[i].type != JSMN_ARRAY) {
        return false;  // we expect "pools" to be an array of array
      }
      const int poolCount = t[i].size;

      for (int j = 0; j < poolCount; j++) {
        // we expect pools to be an array: 3 elements
        int idx = i + 1 + j*4;
        if (t[idx].type != JSMN_ARRAY || t[idx].size != 3) {
          return false;
        }

        PoolConf conf;
        conf.host_ = getJsonStr(c, &t[idx + 1]);
        conf.port_ = (uint16_t)strtoul(getJsonStr(c, &t[idx + 2]).c_str(), NULL, 10);
        conf.upPoolUserName_= getJsonStr(c, &t[idx + 3]);

        poolConfs.push_back(conf);
      }
      i += poolCount * 4;
    }
    else if (jsoneq(c, &t[i], "always_keep_downconn") == 0) {
      string opt = getJsonStr(c, &t[i+1]);
      std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
      alwaysKeepDownconn = (opt == "true");
      i++;
    }
    else if (jsoneq(c, &t[i], "disconnect_when_lost_asicboost") == 0) {
      string opt = getJsonStr(c, &t[i + 1]);
      std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
      disconnectWhenLostAsicBoost = (opt == "true");
      i++;
    }
    else if (jsoneq(c, &t[i], "use_ip_as_worker_name") == 0) {
      string opt = getJsonStr(c, &t[i + 1]);
      std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
      useIpAsWorkerName = (opt == "true");
      i++;
    }
    else if (jsoneq(c, &t[i], "submit_response_from_server") == 0) {
      string opt = getJsonStr(c, &t[i + 1]);
      std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
      submitResponseFromServer = (opt == "true");
      i++;
    }
    else if (jsoneq(c, &t[i], "encrypting") == 0) {
      string opt = getJsonStr(c, &t[i + 1]);
      std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
      encrypting = (opt == "true");
      i++;
    }
    else if (jsoneq(c, &t[i], "fixed_worker_name") == 0) {
      fixedWorkerName = getJsonStr(c, &t[i+1]);
      i++;
    }
  }

  // check parametes
  if (listenIP.length() && listenPort.length() && poolConfs.size()) {
    return true;
  }

  return false;
}

const char *splitNotify(const string &line, int number) {
  const char *pch = strchr(line.c_str(), '"');
  int i = 1;
  while (pch != NULL) {
    pch = strchr(pch + 1, '"');
    i++;
    if (pch != NULL && i == number) {
      break;
    }
  }
  if (pch == NULL) {
    LOG(ERROR) << "invalid mining.notify: " << line << std::endl;
    return NULL;
  }
  return pch;
}

string str2lower(const string &str) {
  string data = str;
  std::transform(data.begin(), data.end(), data.begin(), ::tolower);
  return data;
}

bool strEmpty(const string &str) {
  return str.find_last_not_of(" \t\f\v\n\r") == str.npos;
}

unsigned int simpleHash( string str)
{
    uint32_t seed = 131;
    uint32_t hash = 0;
    int p=0;
    int l=str.size();
    while (l>p) {
        hash = hash * seed + (unsigned char)(str[p]);
        p++;
    }
    return (hash & 0x7FFFFFFF); 
}

std::string chToHex(unsigned char ch)
{
	const std::string hex = "0123456789abcdef";
 
	std::stringstream ss;
	ss << hex[ch >> 4] << hex[ch & 0xf];
 
	return ss.str();
}


/**
 * #purpose	: 字符串转十六进制字符串
 * #note	: 可用于汉字字符串
 * #param str		: 要转换成十六进制的字符串
 * #param separator	: 十六进制字符串间的分隔符
 * #return	: 接收转换后的字符串
 */
string strToHex(string str, std::string separator)
{
	const std::string hex = "0123456789abcdef";
	std::stringstream ss;
 
	for (std::string::size_type i = 0; i < str.size(); ++i)
		ss << hex[(unsigned char)str[i] >> 4] << hex[(unsigned char)str[i] & 0xf] << separator;
  return ss.str();
}

string strHex2StrObj(string hex) {
  int len = hex.length();
  std::string newString;
  for(int i=0; i< len; i+=2)
  {
      string byte = hex.substr(i,2);
      char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
      newString.push_back(chr);
  }
  return newString;
}