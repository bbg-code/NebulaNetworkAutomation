using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NebulaNetworkAutomation
{
    internal class CPEM
    {
        const string c_Begin = "BEGIN ";
        const string c_End = "END ";
        const string c_Split = "-----";

        string m_header = "";
        string m_value = "";

        public string Header => m_header;
        public string Value => m_value;
        public byte[] Bytes => System.Convert.FromBase64String(m_value);

        public string PEM =>
            c_Split + c_Begin + m_header + c_Split + Environment.NewLine +
            m_value + Environment.NewLine +
            c_Split + c_End + m_header + c_Split;

        CPEM(string inHeader, byte[] inValue)
        {
            m_header = inHeader;
            m_value = System.Convert.ToBase64String(inValue, Base64FormattingOptions.InsertLineBreaks);
        }
        CPEM(string inHeader, string inValue)
        {
            m_header = inHeader;
            m_value = inValue;
        }
        public static string? CleanFirebasePEM(string inStr)
        {
            if (inStr == null)
                return null;

            string[] strParts = inStr.Split("-----");
            if (strParts.Length != 5)
                return null;

            strParts[2] = strParts[2].Trim();
            strParts[2] = strParts[2].Replace(" ", Environment.NewLine);
            return
                "-----" + strParts[1] + "-----" + Environment.NewLine +
                 strParts[2] + Environment.NewLine +
                "-----" + strParts[3] + "-----";
        }
        public static CPEM? FromBytes(byte[] inData, string inHeader)
        {
            return new CPEM(inHeader, inData);
        }
        public static CPEM? FromString(string? inStr, string? inExpectedHeader = null)
        {
            if (inStr == null)
                return null;

            string[] strParts = inStr.Split(c_Split);
            if (strParts.Length != 5)
                return null;

            if (!strParts[1].StartsWith(c_Begin))
                return null;
            if (strParts[1].Length < (c_Begin.Length +1))
                return null;
            strParts[1] = strParts[1].Substring(c_Begin.Length);

            if (!strParts[3].StartsWith(c_End))
                return null;
            if (strParts[3].Length < (c_End.Length+1))
                return null;
            strParts[3] = strParts[3].Substring(c_End.Length);


            if (strParts[1] != strParts[3])
                return null;

            if ((inExpectedHeader != null) && (inExpectedHeader!= strParts[1]))
                return null;

            strParts[2] = strParts[2].Trim();

            return new CPEM(strParts[1], strParts[2]);
        }
    }
}
