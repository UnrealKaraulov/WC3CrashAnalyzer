using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;

namespace Wc3CrashAnalyzer
{
    internal class Program
    {
        // For parser Funcitons.txt and VTABLES.txt
        const uint BASE_GAMEDLL_ADDR = 0x6F000000;

        static Regex gamedllregex = new Regex(@"0x(\w+).*?0x.*?:.*?Game\.dll");

        static Regex addr_get_regex1 = new Regex(@"=(\w\w\w\w\w\w\w\w)");
        static Regex addr_get_regex2 = new Regex(@"0x(\w\w\w\w\w\w\w\w)");
        static Regex addr_get_regex3 = new Regex(@"\w+:\s+(\w+\s\w+\s\w+\s\w+)\s+(\w+\s\w+\s\w+\s\w+)\s+(\w+\s\w+\s\w+\s\w+)\s+(\w+\s\w+\s\w+\s\w+)");

        static Regex get_dump_addr = new Regex(@"(\w+\w+)(\w+\w+)(\w+\w+)(\w+\w+)");

        static Regex func_get_regex = new Regex(@"The\sinstruction\sat\s'0x(\w+)'");
        

        static Regex vtable_get_regex = new Regex(@"(\w+)=(.*)");

        static uint GetGameDllAddr(string[] data, ref int line)
        {
            line = 0;
            foreach (string s in data)
            {
                line++;
                Match match = gamedllregex.Match(s);
                if (match.Success)
                {
                    return Convert.ToUInt32(match.Groups[1].Value, 16);
                }
            }
            return 0;
        }

        static bool GetFunctionAddr(string[] data, ref uint funcaddr)
        {
            for (int i = 0; i < data.Length && i < 40; i++)
            {
                Match match = func_get_regex.Match(data[i]);
                if (match.Success)
                {
                    funcaddr = Convert.ToUInt32(match.Groups[1].Value, 16);
                    return true;
                }
            }

            return false;
        }

        static bool IsValidGameDllAddr(uint gamedll, uint inputaddr)
        {
            Int64 gamedlladdr64 = gamedll;
            Int64 inputaddr64 = inputaddr;

            if (inputaddr64 >= gamedlladdr64 && inputaddr64 < gamedlladdr64 + 0xBB5000)
            {
                return true;
            }
            return false;
        }

        static bool IsValidFile(string[] data)
        {
            if (data.Length < 10)
                return false;
            if (data[0].StartsWith("=========="))
                return true;
            return false;
        }

        static List<uint> functionlist = new List<uint>();

        static void ParseFunctionList()
        {
            string[] funclist = File.ReadAllLines("Functions.txt");
            foreach (string s in funclist)
            {
                if (s.Length == 8)
                {
                    functionlist.Add(Convert.ToUInt32(s, 16) - BASE_GAMEDLL_ADDR);
                }
            }
            functionlist.Reverse();
        }

        struct VFTABLE
        {
            public string name;
            public uint addr;
        }

        static List<VFTABLE> vftableList = new List<VFTABLE>();

        static void ParseVirtualTables()
        {
            VFTABLE vFTABLE = new VFTABLE();
            string[] funclist = File.ReadAllLines("VTABLES.txt");
            foreach (string s in funclist)
            {
                Match match = vtable_get_regex.Match(s);
                if (match.Success)
                {
                    vFTABLE.addr = Convert.ToUInt32(match.Groups[1].Value, 16) - BASE_GAMEDLL_ADDR;
                    vFTABLE.name = match.Groups[2].Value;
                    vftableList.Add(vFTABLE);
                }
            }
        }

        static uint GetBetterFuncAddr(uint funcoffset)
        {
            foreach (uint i in functionlist)
            {
                if (funcoffset > i)
                    return i;
            }
            return 0;
        }

        static List<uint> main_crash_offsets = new List<uint>();
        static List<uint> dump_crash_offsets = new List<uint>();

        static void FillMainCrashOffsetList(uint gamedll, string[] data)
        {
            foreach (string s in data)
            {
                foreach (Match match in addr_get_regex1.Matches(s))
                {
                    if (IsValidGameDllAddr(gamedll, Convert.ToUInt32(match.Groups[1].Value, 16)))
                    {
                        main_crash_offsets.Add(Convert.ToUInt32(match.Groups[1].Value, 16) - gamedll);
                    }
                }
                foreach (Match match in addr_get_regex2.Matches(s))
                {
                    if (IsValidGameDllAddr(gamedll, Convert.ToUInt32(match.Groups[1].Value, 16)))
                    {
                        main_crash_offsets.Add(Convert.ToUInt32(match.Groups[1].Value, 16) - gamedll);
                    }
                }
            }
        }

        public static uint ParseDumpAddr(string s)
        {
            Match match = get_dump_addr.Match(s);

            if (match.Success)
            {
                string targetstr = match.Groups[4].Value + match.Groups[3].Value + match.Groups[2].Value + match.Groups[1].Value;
                return Convert.ToUInt32(targetstr, 16);
            }

             return 0;
        }

        static void FillDumpCrashOffsetList(uint gamedll, string[] data)
        {
            foreach (string s in data)
            {
                Match match = addr_get_regex3.Match(s);
                if (match.Success)
                {
                    uint addr1 = ParseDumpAddr(match.Groups[1].Value.Replace(" ", ""));
                    uint addr2 = ParseDumpAddr(match.Groups[2].Value.Replace(" ", ""));
                    uint addr3 = ParseDumpAddr(match.Groups[3].Value.Replace(" ", ""));
                    uint addr4 = ParseDumpAddr(match.Groups[4].Value.Replace(" ", ""));

                    if (IsValidGameDllAddr(gamedll, addr1))
                    {
                        dump_crash_offsets.Add(addr1 - gamedll);
                    }

                    if (IsValidGameDllAddr(gamedll, addr2))
                    {
                        dump_crash_offsets.Add(addr2);
                    }

                    if (IsValidGameDllAddr(gamedll, addr3))
                    {
                        dump_crash_offsets.Add(addr3);
                    }

                    if (IsValidGameDllAddr(gamedll, addr4))
                    {
                        dump_crash_offsets.Add(addr4);
                    }

                    continue;
                }
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Анализатер Game.dll крашей by Karaulov версия: 0.000000000000001f");

            if (!File.Exists("Functions.txt"))
            {
                Console.WriteLine("Отсутствует наикрутейшая база данных функций Functions.txt !");
                Console.ReadKey();
                return;
            }

            ParseFunctionList();

            Console.WriteLine("Загружен список из " + functionlist.Count + " функций Game.dll.");

            if (!File.Exists("VTABLES.txt"))
            {
                Console.WriteLine("Отсутствует наикрутейшая база данных таблиц виртуальных функций VTABLES.txt !");
                Console.ReadKey();
                return;
            }

            ParseVirtualTables();

            Console.WriteLine("Загружен список из " + vftableList.Count + " виртуальных таблиц Game.dll.");

            Console.WriteLine("Опрокиньте сюда файлик текстовый с крашем:");
            string crashfilename = Console.ReadLine().Replace("\"", "");
            if (File.Exists(crashfilename))
            {
                string[] crashfiledata = File.ReadAllLines(crashfilename);
                if (IsValidFile(crashfiledata))
                {
                    int line = 0;
                    uint gamedll = GetGameDllAddr(crashfiledata, ref line);
                    if (gamedll == 0)
                    {
                        Console.WriteLine("Нимагу найти game.dll в краше. Буду думать что это 0x6F000000");
                    }
                    Console.WriteLine("Game.dll адрес = " + gamedll.ToString("X6"));

                    Console.WriteLine("Очистка от посторонних данных...");

                    List<string> newcrashdata = new List<string>();
                    bool addline = true;

                    foreach (string s in crashfiledata)
                    {
                        if (s.Contains("Loaded Modules"))
                            addline = false;

                        if (addline)
                        {
                            newcrashdata.Add(s);
                        }

                        if (s.Contains("Memory Dump"))
                            addline = true;
                    }

                    Console.WriteLine("Почистили файл от мусора теперь данных " + newcrashdata.Count + " из " + crashfiledata.Length);

                    crashfiledata = newcrashdata.ToArray();

                    Console.WriteLine("Начинается сверхбыстрый поиск крашей Game.dll !");
                    uint funcaddr = 0;
                    if (GetFunctionAddr(crashfiledata, ref funcaddr))
                    {
                        Console.WriteLine("Адрес инструкции по которой произошел краш: " + funcaddr.ToString("X6"));
                        if (IsValidGameDllAddr(gamedll, funcaddr))
                        {
                            Console.WriteLine("Крашнула определенно функция в Game.dll");
                            uint realfuncoffset = funcaddr - gamedll;
                            uint parsedfuncoffset = GetBetterFuncAddr(realfuncoffset);
                            Console.WriteLine("Краш произошел в функции sub_6F" + parsedfuncoffset.ToString("X6"));
                        }

                    }
                    else
                    {
                        Console.WriteLine("Печалька но не найден адрес инструкции краша... :(");
                        Console.WriteLine("Ну и ладна хрен с ним!");
                    }

                    Console.WriteLine("Заполняем адресами возможных мест крашей...");
                    FillMainCrashOffsetList(gamedll, crashfiledata);
                    FillDumpCrashOffsetList(gamedll, crashfiledata);
                    Console.WriteLine("Заполнено валидных " + main_crash_offsets.Count + " основных и " + dump_crash_offsets.Count + " второстепенных оффсетов.");

                    Console.WriteLine("Выводим последовательно изъятую информацию о краше:");

                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("-----------------------------------------------------");

                    foreach (uint addr in main_crash_offsets)
                    {
                        bool foundvtable = false;

                        foreach (var vftable in vftableList)
                        {
                            if (addr == vftable.addr)
                            {
                                foundvtable = true;
                                Console.WriteLine("Краш связан с : " + vftable.name);
                                break;
                            }
                        }

                        if (!foundvtable)
                        {
                            uint parsedfuncoffset = GetBetterFuncAddr(addr);
                            Console.WriteLine("С крашем связана функция : sub_6F" + parsedfuncoffset.ToString("X6"));
                        }
                    }

                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("Нажмите любую клавишу для продолжения анализа...");
                    Console.ReadKey();

                    Console.WriteLine("Далее данные изъятые из мусорных (dump) данных вероятно не имеющих ценность:");
                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("-----------------------------------------------------");
                    foreach (uint addr in dump_crash_offsets)
                    {
                        bool foundvtable = false;

                        foreach (var vftable in vftableList)
                        {
                            if (addr == vftable.addr)
                            {
                                foundvtable = true;
                                Console.WriteLine("Возможно краш связан с :" + vftable.name);
                                break;
                            }
                        }

                        if (!foundvtable)
                        {
                            uint parsedfuncoffset = GetBetterFuncAddr(addr);
                            Console.WriteLine("Возможно с крашем связана функция : sub_6F" + parsedfuncoffset.ToString("X6"));
                        }
                    }

                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("-----------------------------------------------------");
                    Console.WriteLine("Ну как инфо, норм? :) ");
                }
                else
                {
                    Console.WriteLine("Шо за говно ты мне кинул?");
                }
            }
            else
            {
                Console.WriteLine("Ты не ахренел кидать несуществующий файл?");
            }

            Console.ReadKey();
        }
    }
}
