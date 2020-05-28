class CheckNative
    {
            public static bool IsDotNetAssembly(string peFile)
            {
                uint peHeader, peHeaderSignature, timestamp, pSymbolTable, noOfSymbol;
                ushort machine, sections, optionalHeaderSize, characteristics, dataDictionaryStart;

                uint[] dataDictionaryRVA = new uint[16];
                uint[] dataDictionarySize = new uint[16];

                try
                {
                    using (Stream fs = new FileStream(peFile, FileMode.Open, FileAccess.Read))
                    {
                        using (var reader = new BinaryReader(fs))
                        {
                            fs.Position = 60;
                            peHeader = reader.ReadUInt32();
                            fs.Position = peHeader;
                            peHeaderSignature = reader.ReadUInt32();
                            machine = reader.ReadUInt16();
                            sections = reader.ReadUInt16();
                            timestamp = reader.ReadUInt32();
                            pSymbolTable = reader.ReadUInt32();
                            noOfSymbol = reader.ReadUInt32();
                            optionalHeaderSize = reader.ReadUInt16();
                            characteristics = reader.ReadUInt16();

                            dataDictionaryStart = Convert.ToUInt16(Convert.ToUInt16(fs.Position) + 96);
                            fs.Position = dataDictionaryStart;
                            for (int i = 0; i < 15; i++)
                            {
                                dataDictionaryRVA[i] = reader.ReadUInt32();
                                dataDictionarySize[i] = reader.ReadUInt32();
                            }
                            return dataDictionaryRVA[14] == 0 ? false : true;
                        }
                    }
                }
                catch (Exception ex) { File.WriteAllText("Error.txt", ex.Message); return false; }
            }

            public static bool IsAssembly(string file)
            {
                try
                {
                    Assembly.LoadFile(file);
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            public static bool IsReflection(string filename)
            {
                try
                {
                    AssemblyName.GetAssemblyName(filename);
                    return true;
                }
                catch { return false; }
            }

            public static bool IsManagedAssembly(string fileName)
            {
                try
                {
                    using (Stream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
                    using (var binaryReader = new BinaryReader(fileStream))
                    {
                        if (fileStream.Length < 64) return false;

                        // Заголовок PE начинается @ 0x3C (60). Его заголовка 4 байта.
                        fileStream.Position = 0x3C;
                        uint peHeaderPointer = binaryReader.ReadUInt32();
                        if (peHeaderPointer == 0)
                        {
                            peHeaderPointer = 0x80;
                        }

                        // Обеспечить, по крайней мере, достаточно места для следующих структур:
                        //     24 byte PE Signature & Header
                        //     28 byte Standard Fields         (24 bytes for PE32+)
                        //     68 byte NT Fields               (88 bytes for PE32+)
                        // >= 128 byte Data Dictionary Table
                        if (peHeaderPointer > fileStream.Length - 256)
                        {
                            return false;
                        }

                        // Проверить PE сигнатуры. Должны быть равныl 'PE\0\0'.
                        fileStream.Position = peHeaderPointer;
                        uint peHeaderSignature = binaryReader.ReadUInt32();
                        if (peHeaderSignature != 0x00004550)
                        {
                            return false;
                        }

            // Пропустить PEHeader поля
            fileStream.Position += 20;

                    const ushort PE32 = 0x10b, PE32PLUS = 0x20b;

            /* Пропущенный фрагмент должен был зависеть от словаря данных начинаться по-разному в зависимости от того, являемся ли мы PE32 или PE32Plus: */

            // Читаем PE магическое число из стандартных полей для определения формата.
            ushort peFormat = binaryReader.ReadUInt16();
                    if (peFormat != PE32 && peFormat != PE32PLUS) return false;

                    // Читаем 15-й полевой словарь данных RVA, который содержит командной строкой заголовка RVA.
                    // При этом не равно нулю, то файл содержит сведения CLI иначе нет.
                    ushort dataDictionaryStart = (ushort)(peHeaderPointer + (peFormat == PE32 ? 232 : 248));
            fileStream.Position = dataDictionaryStart;
                    return binaryReader.ReadUInt32() == 0 ? false : true;
                }
    }
            catch (Exception ex) { File.WriteAllText("Error.txt", ex.Message); return false; };
        }

            public static bool IsGetPEKind(string file)
{
    try
    {
        var assembly = Assembly.ReflectionOnlyLoadFrom(file);
        assembly.ManifestModule.GetPEKind(out PortableExecutableKinds kinds, out ImageFileMachine imgFileMachine);
        return true;
    }
    catch (Exception) { return false; }
}
    }
