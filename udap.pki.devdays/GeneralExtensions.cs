#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace udap.pki.devdays;

public static class GeneralExtensions
{
    public static void EnsureDirectoryExists(this string source)
    {
        if (!Directory.Exists(source))
        {
            Directory.CreateDirectory(source);
        }
    }

    public static void EnsureDirectoryExistFromFilePath(this string source)
    {
        var directoryPath = Path.GetDirectoryName(source);
        if (directoryPath != null)
        {
            EnsureDirectoryExists(directoryPath);
        }
    }
}