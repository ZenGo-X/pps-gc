use crate::circuits::byte_array::BytesBundle;

pub fn join3<'a, W, const M: usize, const L: usize, const N: usize>(
    table1: &'a [[BytesBundle<W, N>; L]; M],
    table2: &'a [[BytesBundle<W, N>; L]; M],
    table3: &'a [[BytesBundle<W, N>; L]; M],
) -> impl Iterator<
    Item = impl Iterator<
        Item = (
            &'a BytesBundle<W, N>,
            &'a BytesBundle<W, N>,
            &'a BytesBundle<W, N>,
        ),
    >,
> {
    let joint_rows = table1.iter().zip(table2.iter()).zip(table3.iter());

    joint_rows.map(|((row1, row2), row3)| {
        row1.iter()
            .zip(row2.iter())
            .zip(row3.iter())
            .map(|((item1, item2), item3)| (item1, item2, item3))
    })
}
