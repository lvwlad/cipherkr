#ifndef KUZ_CALC_H
#define KUZ_CALC_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <iostream>

#define BLCK_SIZE 16 /// Размер блока
#define KEY_SIZE  32 /// Размер ключа
#define VECT_SIZE 16 /// Размер вектора инициализации
#define STR_SIZE  32 /// Максимальный размер строки

/*
* значения для нелинейного преобразования
* множества двоичных векторов (преобразование S)
*/
extern const unsigned char Pi[256];

/*
* массив коэффицентов для R-преобразования
*/
extern const unsigned char l_vec[16];

typedef uint8_t vect[BLCK_SIZE]; /// Определяем тип vect как 16-байтовый массив

class Kuznechik
{
public:
    /*!
     * \brief CTR_Crypt - шифрование в режиме гаммирования без усечения гаммы
     * \param init_vec - вектор инициализации
     * \param in_buf - входные данные
     * \param out_buf - буфер для результата
     * \param key - ключ шифрования
     * \param size - размер данных
     */
    void CTR_Crypt(uint8_t *init_vec, uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size);
    //void GOST_Kuz_Decrypt(const uint8_t *blk, uint8_t *out_blk);

private:
    /*!
     * \brief GOST_Kuz_Expand_Key - Разворачивания ключа
     * \param key - ключ
     */
    void GOST_Kuz_Expand_Key(const uint8_t *key);

    /*!
     * \brief GOST_Kuz_Destroy_Key - Уничтожения ключа
     */
    void GOST_Kuz_Destroy_Key();

    /*!
     * \brief GOST_Kuz_Encrypt - шифрование 1 блока данных
     * \param blk - незашифрованный блок
     * \param out_blk - блок после раунда шифрования
     */
    void GOST_Kuz_Encrypt(const uint8_t *blk, uint8_t *out_blk);

    /*!
     * \brief GOST_Kuz_S - функция S преобразования
     * \param in_data - данные на вход
     * \param out_data - данные на выход
     */
    void GOST_Kuz_S(const uint8_t *in_data, uint8_t *out_data);

    /*!
     * \brief GOST_Kuz_X - Сложение двух двоичных векторов по модулю 2
     * \param a - первый вектор
     * \param b - второй вектор
     * \param c - третий вектор
     */
    void GOST_Kuz_X(const uint8_t *a, const uint8_t *b, uint8_t *c);

    /*!
     * \brief GOST_Kuz_GF_mul - умножения чисел в конечном поле Галуа
     * \param a - число
     * \param b - множитель
     * \return произведение
     */
    uint8_t GOST_Kuz_GF_mul(uint8_t a, uint8_t b);

    /*!
     * \brief GOST_Kuz_R - функция R-преобразования
     * \param state - состояние
     */
    void GOST_Kuz_R(uint8_t *state);

    /*!
     * \brief GOST_Kuz_L - Линейное преобразование L
     * \param in_data - данные на вход
     * \param out_data - данные на выход
     */
    void GOST_Kuz_L(const uint8_t *in_data, uint8_t *out_data);

    /*!
     * \brief GOST_Kuz_Get_C - вычисление итерационных констант
     */
    void GOST_Kuz_Get_C();

    /*!
     * \brief GOST_Kuz_F - итерация развертывания ключа
     * \param in_key_1 - ключ 1 до преобразования
     * \param in_key_2 - ключ 2 до преобразования
     * \param out_key_1 - ключ 1 после преобразования
     * \param out_key_2 - ключ 1 после преобразования
     * \param iter_const - итерационная константа
     */
    void GOST_Kuz_F(const uint8_t *in_key_1, const uint8_t *in_key_2, uint8_t *out_key_1, uint8_t *out_key_2, uint8_t *iter_const);

    /*!
     * \brief inc_ctr - увеличение счетчика
     * \param ctr - указатель на счетчик
     */
    void inc_ctr(uint8_t *ctr);

    /*!
     * \brief add_xor - сложение исключающим или
     * \param a - слогаемое 1
     * \param b - слогаемое 2
     * \param c - результат сложения
     */
    void add_xor(const uint8_t *a, const uint8_t *b, uint8_t *c);

private:
    vect iter_C[32]; /// итерационные константы C
    vect iter_key[10]; /// итерационные ключи шифрования
};

/*!
 * \brief reverse_array - переворот массива
 * \param array - массив
 * \param size - размер массива
 */
void reverse_array(unsigned char *array, int size);

/*!
 * \brief convert_hex - конвертировать массива char в uint8_t
 * \param dest - назначение
 * \param src - источник
 * \param count - размер
 * \return сколько элементов конвертировано
 */
size_t convert_hex(uint8_t *dest, const char *src, size_t count);

/*!
 * \brief convert_to_string - конвертировать массива char в string
 * \param arr - массив char
 * \param size - размер массива
 * \return строка
 */
std::string convert_to_string(const unsigned char* arr, size_t size);

/*!
 * \brief reverse_hex - побайтовый переворот строки
 * \param str - строка
 * \return перевернутая строка
 */
std::string reverse_hex(std::string str);

#endif // KUZ_CALC_H
