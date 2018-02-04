/*
* Copyright (c) 2018 ZeroPass
* Distributed under the MIT software license, see the accompanying
* file LICENSE or https://opensource.org/licenses/MIT.
*/


package io.zeropass.trid.tlv;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.logging.Logger;


class ASN1Util implements ASN1Constants {

  private static final Logger Journal = Logger.getLogger("io.trid.asn1utils");
  private static final String SDF = "yyMMddhhmmss'Z'";

  static Object interpretPrimitiveValue(int tag, byte[] valueBytes) {
    SimpleDateFormat sdf = new SimpleDateFormat(SDF);
    if (TLVUtils.getTagClass(tag) != UNIVERSAL_CLASS) {
      return valueBytes;
    }

    switch (tag) {
      case INTEGER_TYPE_TAG:
      case BIT_STRING_TYPE_TAG:
      case OCTET_STRING_TYPE_TAG:
      case NULL_TYPE_TAG:
      case OBJECT_IDENTIFIER_TYPE_TAG:
        return valueBytes;
      case UTF8_STRING_TYPE_TAG:
      case PRINTABLE_STRING_TYPE_TAG:
      case T61_STRING_TYPE_TAG:
      case IA5_STRING_TYPE_TAG:
      case VISIBLE_STRING_TYPE_TAG:
      case GENERAL_STRING_TYPE_TAG:
      case UNIVERSAL_STRING_TYPE_TAG:
      case BMP_STRING_TYPE_TAG:
        return new String(valueBytes);
      case UTC_TIME_TYPE_TAG:
        try {
          return sdf.parse(new String(valueBytes));
        } catch (ParseException pe) {
          Journal.warning("Error parsing UTC time" + pe);
          return valueBytes;
        }
      default:
        return valueBytes;          
    }
  }
}
