namespace WinUp
{
    // Словарь пароль-фраз: русские слова латиницей (ж=zh, ш=sh, ч=ch, х=h, ц=ts, я=ya, ю=yu, ы=y, й=i, ь опущен).
    // Латиница — чтобы фраза набиралась в любой раскладке: ошибка раскладки в пароле базы стоит попытки,
    // а после последней база уничтожается. Только нарицательные существительные, 3–9 букв, без повторов.
    static class PassphraseWords
    {
        public const string All =
            "abrikos avans avgust avokado avtobus avtor agent adres aist akkord akter akula albom alleya almaz alfavit " +
            "ananas angar anekdot anis anons antenna apelsin aprel apteka arbuz arena arka arfa aromat artist asfalt astra " +
            "atlas atom aura avrora aeroport ambar bassein budilnik baget bagazh baza baikal balet balkon bamper banan " +
            "bank banka bant baraban baran barhat barsuk bashnya basket baton batut bekon belka bereg bereza beseda beton " +
            "bidon bizon bilet binokl biser biskvit blesk blin blok bloknot bluzka bob bobr boks boloto botinok brat " +
            "bronza bruk brusnika bublik buket bukva bulka bulvar buran burya butik buton buhta byk bumaga banya vagon " +
            "vaza valenok vanil vanna varenik varenye veer vezdehod vek venok veranda verba verblyud veresk verevka " +
            "vershina vesna veter vecher vetka vid video vilka vino vinograd vitamin vitrina vishnya vkus vlaga voda " +
            "vodopad vokzal volk volna volos vorona vorota vosk vtornik vulkan vyshka vyuga vozduh vertolet vesy gavan " +
            "gazeta gazon galka galstuk gamak gamma garazh garmon gaz gvozd gepard gerb geroi gimn gips gitara glaz glina " +
            "globus gnezdo gobelen golub gora gorod goroh gorizont gorka gorn gorshok gost gramota granat granit graf " +
            "grafin gribok grib grifel grom grusha gryadka gubka gus gusenitsa gusli gnom golova gruzovik dacha dvor " +
            "dvorets delfin den depo derevo desert detal dzhem diagramma diamant divan dieta dikobraz diplom disk dobro " +
            "dozhd dok doklad dolina dom domino doroga doska drakon drova drozd drug dub dudka duh dush dym dynya dyatel " +
            "domik eda ekran elka ezh enot zhaba zhaket zhasmin zhele zhemchug zhivopis zhiraf zhuk zhurnal zhuravl zhilet " +
            "zabor zavod zagadka zakat zal zaliv zamok zapad zapah zarya zayats zvezda zvon zebra zemlya zenit zerkalo " +
            "zerno zima zmei znak znamya zoloto zont zontik zoopark zub zubr zvonok iva igla igra igrushka izba izyum ikra " +
            "imbir indeika inei iris iskra istok istoriya iyul iyun izumrud kabachok kabel kadr kazan kaktus kalach " +
            "kalendar kalina kalmar kamen kamin kanal kapel kapitan kapusta karamel karandash karas karman karnaval karp " +
            "karta kartina kartofel karusel kasha kaska kassa kater katok kafe kakao kashtan kvadrat kvartira kvas kedr " +
            "kefir keks kenguru kepka kivi kino kiosk kirpich kisel kist kit klad klass klen klever klyuch kloun klub " +
            "klubnika klubok klumba knopka kniga kobra kover kovsh koza kokos kolba kolbasa koleso kolibri kolodets " +
            "kolokol kolos kolpak komar kometa komod kompas kompot konfeta konus konvert kontur kopilka kora korabl " +
            "korzina koritsa korobka korona korova kosmos koster kot kotenok kotel kofe kofta koshka kran krab kraska " +
            "kreslo krem krepost krovat krokodil krolik krona kroshka krug kruzhka krupa krysha kub kubik kubok kuvshin " +
            "kukla kukuruza kulon kupol kurort kurtka kust kuhnya kanikuly kaplya komnata korzinka kostyum kotleta krasota " +
            "labirint lava lavanda lavka ladon lama lampa landysh lapa lapsha lastochka lebed led ledenets ledokol lemur " +
            "lenta les lestnitsa leto letchik lev legenda lepestok limon lineika lipa list litr lift lis lisa lodka lozhka " +
            "lokomotiv lomtik loshad losos lotos lotok lug luk luna lupa luch lyzhi lyustra lednik liliya mayak mai mak " +
            "maket malina mamont mandarin mango manezh marka marmelad marshrut maska maslo master matras med medal medved " +
            "meduza mel melodiya mesyats metla metro mechta mir miska molniya moloko molot moneta more moroz morkov mors " +
            "most motor muzei muzyka muka muravei myach mylo myshka myata magazin magnit mandolina mashina mebel metel " +
            "mikser minuta model molotok mozaika muzykant nabor nadezhda nasos nebo nedelya nektar nerpa nitka noch noga " +
            "nozh nomer nora norka nos nosok nota noyabr nauka obed oblako ovrag ovsyanka ogon ogorod ogurets odeyalo " +
            "ozero okean okno oktyabr olen olivka omlet opal opera orbita orel oreh orkestr osa osen ostrov osminog otel " +
            "otpusk ofis ohota otkrytka ochki pavlin palatka palets palma palitra palto panda panama papka par park parket " +
            "parus pasta pastila pauk pasport pelikan pena penal perets pero perron pesnya pesok pechenye pila pilot " +
            "pingvin pion piramida pirog pirozhok pismo plakat plamya plan planeta plita plot plyazh pogoda poezd pole " +
            "polka polyana pomidor ponchik poni portfel port posylka potok poyas prazdnik priboi prostor prud ptitsa pudel " +
            "puh pustynya pchela parovoz pianino pidzhak pirat plastilin podarok podkova podushka polet posuda pryanik " +
            "pugovitsa pylesos pechka radar raduga raketa rakushka ramka rassvet rak ranets rebus redis reka ris risunok " +
            "robot rodnik roza rogalik roman romashka rosa rubin ruchei ruka rukav rulet ruchka ryba rybak ryukzak ryabina " +
            "radio rulon rusalka sad salat salyut samolet sandal sani sapog sapfir sardina sahar svecha svet sviter sever " +
            "sekret seno sentyabr serebro sestra sinitsa siren skakalka skala skameika skvorets skazka skrepka skripka " +
            "sliva slon sneg snegir sobaka sova sok sokol solntse solovei soloma sosna sosulka sota spichka sport sputnik " +
            "stakan stena stol stolitsa strana strela strekoza struna stul sudak sumka sunduk sup suslik syr syrok " +
            "salfetka samovar svitok sekunda skatert slovo snezhok soroka stadion stolb strizh syrnik taiga talant tanets " +
            "tarelka teatr tekst telefon telezhka teleskop terem tetrad tigr tishina tomat topor tort tochka trava traktor " +
            "tramvai tron tropa truba tuman tufli tukan tulpan tunnel turist tykva tyulen tablitsa tachka telenok teplitsa " +
            "toster tuchka tyubik uzor ukrop ulitka ulitsa ulei ulybka uragan urozhai urok utka utro utyug fabrika fazan " +
            "fakel fantik fara farfor fartuk fasol fevral feya feniks festival figura filin film finik flag flakon " +
            "flamingo flomaster flot fokus fonar fontan forel forma foto frukt funduk futbol fanera fialka fonarik halat " +
            "halva hleb hobot hokkei holm hrustal hvost hlopok tsaplya tsvet tsvetok tsentr tsifra tsirk tsitrus chai " +
            "chainik chas chashka chaika chemodan chernika chertezh chesnok chislo chudo chizh cherepaha shar sharf shapka " +
            "shashlyk shelk shina shishka shkaf shkola shlem shmel shnur shokolad shtora shum shutka shuba shalash " +
            "shezlong shkatulka shtorm yabloko yagoda yahta yakor yantar yarmarka yubka yug emblema epoha estrada etazh " +
            "akvarium babochka barometr batareika begemot belyash bolt bort brevno brigada bubenchik bugor bulavka bur " +
            "butylka valun vafli vaksa vasilek vatnik vedro venik vint vitok vobla volan voron vorotnik vyaz vyshivka " +
            "galoshi garderob garpun gastrol gerbarii girlyanda glazur golosok gorelka gorchitsa gosti gravyura greben " +
            "grelka grot gudok dvigatel debyut dekor diktor dirizher dnevnik dozor dokument drel dubrava duet dvornik " +
            "evkalipt ezhevika zhatva zhezl zagar zanaves zaplatka zapiska zastava zayavka zvonar zhenshen zimovie zlak " +
            "zodiak zubilo zyablik ivolga igolka izgorod indigo inspektor kabinet kadka kalosh kamysh kanat kanistra kapot " +
            "kardan karkas kartuz kasatka kaskad katamaran kauchuk kedy kipyatok klapan kleshni klyushka kozhuh kokon " +
            "kokoshnik koltso komok konek kopna kopyto korma korshun kosilka kosynka kotomka kovrik krendel kryazh kulik " +
            "kulich kuvalda kupets kuritsa ladya lager lazur laska leika lepeshka lesnik letopis lezhak lodochnik lokon " +
            "lopata lopatka loskut lubok lyagushka lyuk makovka malyar manka marlya matros mayatnik mazurka medovik " +
            "melnitsa metelka mirazh mokasin molva morshina motyga mushka myaso mysh nagrada nakidka namek naperstok narty " +
            "nastil navigator nazhdak nevod nikel notarius nozhka obruch ogranka okorok oladya opilki oprava ornament " +
            "oskolok otvertka paket palka pantera parik parnik pashtet pastuh parcha patefon payalnik perchatka perila " +
            "perina pesets pinetki pirozhnoe plafon platok pletenka plombir podnos podval pokryvalo poloska pomada popugai " +
            "porosenok poroshok pozharnik primus probka propeller prostynya provod pruzhina pryazha pudra pulover pyure " +
            "rabotnik rabota radiator ragu razvilka repeinik rezina rodina rozhok rubashka rumyanets rupor rysak ryzhik " +
            "saksofon salazki sapozhnik sarafan sarai sapozhok seledka semechko setka sirop skorlupa slastena smola " +
            "sneginka solonka sorochka sosiska spina stavni stebel stoyanka strelka strochka struzhka sukharik sukno " +
            "sumerki surok svekla svirel tabakerka talisman tamburin taburet tapki teremok testo tetiva tkach tolokno " +
            "toporik trubka tryapka tulup turnik tyagach udochka ugolok ulov umyvalnik usadba ushanka uzelok fanfara farsh " +
            "fartushek fedora fermer fishka flyuger fokstrot fortochka fregat fuga fura furazhka hlopushka hokkeist holst " +
            "horovod hutor tsarevna tsikl tsilindr tsinovka chasovoi chelnok cheremuha chizhik chudak chugunok chulok " +
            "chuchelo shalfei shashki shest shilo shipovnik shirma shlyapa shnurok shpinat shpora shtanga shtopor shurup " +
            "yablonya yamshik yashma yastreb yasen ";
    }
}
