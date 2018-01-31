/*
 * This file is part of the SCUBA smart card framework.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Copyright (C) 2009 - 2018  The SCUBA team.
 *
 * $Id: TLVUtil.java 302 2018-01-13 23:54:51Z martijno $
 */


package io.zeropass.trid.libs;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/* FIXME: make class package visible only. */

public class TLVUtil implements ASN1Constants {

  private static final Logger LOGGER = Logger.getLogger("net.sf.scuba");

  /** Hide from public interface. */
  private TLVUtil() {
  }

  public static boolean isPrimitive(int tag) {
    int i = 3;
    for (; i >= 0; i--) {
      int mask = (0xFF << (8 * i));
      if ((tag & mask) != 0x00) {
        break;
      }
    }
    int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
    return ((msByte & 0x20) == 0x00);
  }

  public static int getTagLength(int tag) {
    return getTagAsBytes(tag).length;
  }

  public static int getLengthLength(int length) {
    return getLengthAsBytes(length).length;
  }

  /**
   * The tag bytes of this object.
   *
   * @param tag the tag
   *
   * @return the tag bytes of this object.
   */
  public static byte[] getTagAsBytes(int tag) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int byteCount = (int)(Math.log(tag) / Math.log(256)) + 1;
    for (int i = 0; i < byteCount; i++) {
      int pos = 8 * (byteCount - i - 1);
      out.write((tag & (0xFF << pos)) >> pos);
    }
    byte[] tagBytes = out.toByteArray();
    switch (getTagClass(tag)) {
      case APPLICATION_CLASS:
        tagBytes[0] |= 0x40;
        break;
      case CONTEXT_SPECIFIC_CLASS:
        tagBytes[0] |= 0x80;
        break;
      case PRIVATE_CLASS:
        tagBytes[0] |= 0xC0;
        break;
      default:
        /* NOTE: Unsupported tag class. Now what? */
        break;
    }
    if (!isPrimitive(tag)) {
      tagBytes[0] |= 0x20;
    }
    return tagBytes;
  }

  /**
   * The length bytes of this object.
   *
   * @param length the length
   *
   * @return length of encoded value as bytes
   */
  public static byte[] getLengthAsBytes(int length) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (length < 0x80) {
      /* short form */
      out.write(length);
    } else {
      int byteCount = log(length, 256);
      out.write(0x80 | byteCount);
      for (int i = 0; i < byteCount; i++) {
        int pos = 8 * (byteCount - i - 1);
        out.write((length & (0xFF << pos)) >> pos);
      }
    }
    return out.toByteArray();
  }

  /*
  public static byte[] wrapDO(int tag, byte[] data) {
    if (data == null) {
      throw new IllegalArgumentException("Data to wrap is null");
    }

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try {
      TLVOutputStream tlvOutputStream = new TLVOutputStream(byteArrayOutputStream);
      tlvOutputStream.writeTag(tag);
      tlvOutputStream.writeValue(data);
      tlvOutputStream.flush();
      tlvOutputStream.close();
      return byteArrayOutputStream.toByteArray();
    } catch (IOException ioe) {
      // Never happens
      throw new IllegalStateException("Error writing stream", ioe);
    } finally {
      try {
        byteArrayOutputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
  }*/

  /*
  public static byte[] unwrapDO(int expectedTag, byte[] wrappedData) {
    if (wrappedData == null || wrappedData.length < 2)  {
      throw new IllegalArgumentException("Wrapped data is null or length < 2");
    }

    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(wrappedData);
    TLVInputStream tlvInputStream = new TLVInputStream(byteArrayInputStream);

    try {
      int actualTag = tlvInputStream.readTag();
      if (actualTag != expectedTag) {
        throw new IllegalArgumentException("Expected tag " + Integer.toHexString(expectedTag) + ", found tag " + Integer.toHexString(actualTag));
      }

      int length = tlvInputStream.readLength();
      byte[] value = tlvInputStream.readValue();
      byte[] result = new byte[length];
      System.arraycopy(value, 0, result, 0, length);
      return result;
    } catch (IOException ioe) {
      // Never happens
      throw new IllegalStateException("Error reading from stream", ioe);

    } finally {
      try {
        tlvInputStream.close();
        //        byteArrayInputStream.close();
      } catch (IOException ioe) {
        LOGGER.log(Level.FINE, "Error closing stream", ioe);
      }
    }
  }*/

  static int getTagClass(int tag) {
    int i = 3;
    for (; i >= 0; i--) {
      int mask = (0xFF << (8 * i));
      if ((tag & mask) != 0x00) {
        break;
      }
    }
    int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
    switch (msByte & 0xC0) {
      case 0x00:
        return UNIVERSAL_CLASS;
      case 0x40:
        return APPLICATION_CLASS;
      case 0x80:
        return CONTEXT_SPECIFIC_CLASS;
      case 0xC0:
      default:
        return PRIVATE_CLASS;
    }
  }

  private static int log(int n, int base) {
    int result = 0;
    while (n > 0) {
      n = n / base;
      result ++;
    }
    return result;
  }
}
