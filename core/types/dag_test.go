package types

import (
	"encoding/hex"
	"testing"

	"github.com/golang/snappy"

	"github.com/cometbft/cometbft/libs/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeTxDAGCalldata(t *testing.T) {
	tg := mockSimpleDAG()
	data, err := EncodeTxDAGCalldata(tg)
	assert.Equal(t, nil, err)
	tg, err = DecodeTxDAGCalldata(data)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, tg.TxCount() > 0)

	_, err = DecodeTxDAGCalldata(nil)
	assert.NotEqual(t, nil, err)
}

//func TestDecodeCalldata(t *testing.T) {
//	calldata := "0x5517ed8c000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000003e501f903e1f903dec2c002c1c0c2c101c1c0c2c103c2c104c1c0c2c106c2c107c1c0c2c109c2c10ac1c0c2c10cc2c10dc1c0c2c10fc2c110c1c0c2c112c2c113c1c0c2c115c2c116c1c0c2c118c2c119c1c0c2c11bc2c11cc1c0c2c11ec2c11fc1c0c2c121c2c122c1c0c2c124c2c125c1c0c2c127c2c128c1c0c2c12ac2c12bc1c0c2c12dc2c12ec1c0c2c130c2c131c1c0c2c133c2c134c1c0c2c136c2c137c1c0c2c139c2c13ac1c0c2c13cc2c13dc1c0c2c13fc2c140c1c0c2c142c2c143c1c0c2c145c2c146c1c0c2c148c2c149c1c0c2c14bc2c14cc1c0c2c14ec2c14fc1c0c2c151c2c152c1c0c2c154c2c155c1c0c2c157c2c158c1c0c2c15ac2c15bc1c0c2c15dc2c15ec1c0c2c160c2c161c1c0c2c163c2c164c1c0c2c166c2c167c1c0c2c169c2c16ac1c0c2c16cc2c16dc1c0c2c16fc2c170c1c0c2c172c2c173c1c0c2c175c2c176c1c0c2c178c2c179c1c0c2c17bc2c17cc1c0c2c17ec2c17fc1c0c3c28181c3c28182c1c0c3c28184c3c28185c1c0c3c28187c3c28188c1c0c3c2818ac3c2818bc1c0c3c2818dc3c2818ec1c0c3c28190c3c28191c1c0c3c28193c3c28194c2c102c3c28196c3c28197c2c105c3c28199c3c2819ac2c108c3c2819cc3c2819dc2c10bc3c2819fc3c281a0c2c10ec3c281a2c3c281a3c2c111c3c281a5c3c281a6c2c114c3c281a8c3c281a9c2c117c3c281abc3c281acc2c11ac3c281aec3c281afc2c11dc3c281b1c2c120c3c281b2c3c281b3c3c281b5c2c123c3c281b7c3c281b8c2c126c3c281bac3c281bbc2c129c3c281bdc3c281bec2c12cc3c281c0c3c281c1c2c12fc3c281c3c3c281c4c2c132c3c281c6c3c281c7c2c135c3c281c9c3c281cac2c138c3c281ccc3c281cdc2c13bc3c281cfc3c281d0c2c13ec3c281d2c3c281d3c2c141c3c281d5c3c281d6c2c144c3c281d8c3c281d9c2c147c3c281dbc3c281dcc2c14ac3c281dec3c281dfc2c14dc3c281e1c3c281e2c2c150c3c281e4c3c281e5c2c153c3c281e7c3c281e8c2c156c3c281eac3c281ebc2c159c3c281edc3c281eec2c15cc3c281f0c3c281f1c2c15fc3c281f3c3c281f4c2c162c3c281f6c3c281f7c2c165c3c281f9c3c281fac2c168c3c281fcc3c281fdc2c16bc3c281ffc4c3820100c2c16ec4c3820102c4c3820103c2c171c4c3820105c4c3820106c2c174c4c3820108c4c3820109c2c177c4c382010bc4c382010cc2c17ac4c382010ec4c382010fc2c17dc4c3820111c4c3820112c3c28180c4c3820114c4c3820115c3c28183c4c3820117c4c3820118c3c28186c4c382011ac4c382011bc3c28189c4c382011dc4c382011ec3c2818cc4c3820120c4c3820121c3c2818fc4c3820123c4c3820124c3c28192c4c3820126c4c3820127c2c001000000000000000000000000000000000000000000000000000000"
//	decode, err := hexutil.Decode(calldata)
//	if err != nil {
//		return
//	}
//	dagCalldata, err := DecodeTxDAGCalldata(decode)
//	if err != nil {
//		t.Errorf("Error decoding calldata: %s", err)
//		return
//	}
//	t.Logf("result:%s", dagCalldata)
//	panic("1")
//}

func TestTxDAG_SetTxDep(t *testing.T) {
	dag := mockSimpleDAG()
	require.NoError(t, dag.SetTxDep(9, NewTxDep(nil, NonDependentRelFlag)))
	require.NoError(t, dag.SetTxDep(10, NewTxDep(nil, NonDependentRelFlag)))
	require.Error(t, dag.SetTxDep(12, NewTxDep(nil, NonDependentRelFlag)))
	dag = NewEmptyTxDAG()
	require.NoError(t, dag.SetTxDep(0, NewTxDep(nil, NonDependentRelFlag)))
	require.NoError(t, dag.SetTxDep(11, NewTxDep(nil, NonDependentRelFlag)))
}

func TestTxDAG(t *testing.T) {
	dag := mockSimpleDAG()
	t.Log(dag)
	dag = mockSystemTxDAG()
	t.Log(dag)
}

func TestEvaluateTxDAG(t *testing.T) {
	dag := mockSystemTxDAG()
	EvaluateTxDAGPerformance(dag)
}

func TestTxDAG_Compression(t *testing.T) {
	dag := mockRandomDAG(10000)
	enc, err := EncodeTxDAG(dag)
	require.NoError(t, err)
	encoded := snappy.Encode(nil, enc)
	t.Log("enc", len(enc), "compressed", len(encoded), "ratio", 1-(float64(len(encoded))/float64(len(enc))))
}

func BenchmarkTxDAG_Encode(b *testing.B) {
	dag := mockRandomDAG(10000)
	for i := 0; i < b.N; i++ {
		EncodeTxDAG(dag)
	}
}

func BenchmarkTxDAG_Decode(b *testing.B) {
	dag := mockRandomDAG(10000)
	enc, _ := EncodeTxDAG(dag)
	for i := 0; i < b.N; i++ {
		DecodeTxDAG(enc)
	}
}

func mockSimpleDAG() TxDAG {
	dag := NewPlainTxDAG(10)
	dag.TxDeps[0].TxIndexes = []uint64{}
	dag.TxDeps[1].TxIndexes = []uint64{}
	dag.TxDeps[2].TxIndexes = []uint64{}
	dag.TxDeps[3].TxIndexes = []uint64{0}
	dag.TxDeps[4].TxIndexes = []uint64{0}
	dag.TxDeps[5].TxIndexes = []uint64{1, 2}
	dag.TxDeps[6].TxIndexes = []uint64{5}
	dag.TxDeps[7].TxIndexes = []uint64{6}
	dag.TxDeps[8].TxIndexes = []uint64{}
	dag.TxDeps[9].TxIndexes = []uint64{8}
	return dag
}

func mockRandomDAG(txLen int) TxDAG {
	dag := NewPlainTxDAG(txLen)
	for i := 0; i < txLen; i++ {
		deps := make([]uint64, 0)
		if i == 0 || rand.Bool() {
			dag.TxDeps[i].TxIndexes = deps
			continue
		}
		depCnt := rand.Int()%i + 1
		for j := 0; j < depCnt; j++ {
			var dep uint64
			if j > 0 && deps[j-1]+1 == uint64(i) {
				break
			}
			if j > 0 {
				dep = uint64(rand.Int())%(uint64(i)-deps[j-1]-1) + deps[j-1] + 1
			} else {
				dep = uint64(rand.Int() % i)
			}
			deps = append(deps, dep)
		}
		dag.TxDeps[i].TxIndexes = deps
	}
	return dag
}

func mockSystemTxDAG() TxDAG {
	dag := NewPlainTxDAG(12)
	dag.TxDeps[0].TxIndexes = []uint64{}
	dag.TxDeps[1].TxIndexes = []uint64{}
	dag.TxDeps[2].TxIndexes = []uint64{}
	dag.TxDeps[3].TxIndexes = []uint64{0}
	dag.TxDeps[4].TxIndexes = []uint64{0}
	dag.TxDeps[5].TxIndexes = []uint64{1, 2}
	dag.TxDeps[6].TxIndexes = []uint64{5}
	dag.TxDeps[7].TxIndexes = []uint64{6}
	dag.TxDeps[8].TxIndexes = []uint64{}
	dag.TxDeps[9].TxIndexes = []uint64{8}
	dag.TxDeps[10] = NewTxDep([]uint64{}, ExcludedTxFlag)
	dag.TxDeps[11] = NewTxDep([]uint64{}, ExcludedTxFlag)
	return dag
}

func mockSystemTxDAG2() TxDAG {
	dag := NewPlainTxDAG(12)
	dag.TxDeps[0] = NewTxDep([]uint64{})
	dag.TxDeps[1] = NewTxDep([]uint64{})
	dag.TxDeps[2] = NewTxDep([]uint64{})
	dag.TxDeps[3] = NewTxDep([]uint64{0})
	dag.TxDeps[4] = NewTxDep([]uint64{0})
	dag.TxDeps[5] = NewTxDep([]uint64{1, 2})
	dag.TxDeps[6] = NewTxDep([]uint64{5})
	dag.TxDeps[7] = NewTxDep([]uint64{6})
	dag.TxDeps[8] = NewTxDep([]uint64{})
	dag.TxDeps[9] = NewTxDep([]uint64{8})
	dag.TxDeps[10] = NewTxDep([]uint64{}, NonDependentRelFlag)
	dag.TxDeps[11] = NewTxDep([]uint64{}, NonDependentRelFlag)
	return dag
}

func mockSystemTxDAGWithLargeDeps() TxDAG {
	dag := NewPlainTxDAG(12)
	dag.TxDeps[0].TxIndexes = []uint64{}
	dag.TxDeps[1].TxIndexes = []uint64{}
	dag.TxDeps[2].TxIndexes = []uint64{}
	dag.TxDeps[3].TxIndexes = []uint64{0}
	dag.TxDeps[4].TxIndexes = []uint64{0}
	dag.TxDeps[5].TxIndexes = []uint64{1, 2}
	dag.TxDeps[6].TxIndexes = []uint64{5}
	dag.TxDeps[7].TxIndexes = []uint64{3}
	dag.TxDeps[8].TxIndexes = []uint64{}
	//dag.TxDeps[9].TxIndexes = []uint64{0, 1, 2, 6, 7, 8}
	dag.TxDeps[9] = NewTxDep([]uint64{3, 4, 5}, NonDependentRelFlag)
	dag.TxDeps[10] = NewTxDep([]uint64{}, ExcludedTxFlag)
	dag.TxDeps[11] = NewTxDep([]uint64{}, ExcludedTxFlag)
	return dag
}

func TestTxDAG_Encode_Decode(t *testing.T) {
	tests := []struct {
		expect TxDAG
	}{
		{
			expect: TxDAG(&EmptyTxDAG{}),
		},
		{
			expect: mockSimpleDAG(),
		},
		{
			expect: mockRandomDAG(100),
		},
		{
			expect: mockSystemTxDAG(),
		},
		{
			expect: mockSystemTxDAG2(),
		},
		{
			expect: mockSystemTxDAGWithLargeDeps(),
		},
	}
	for i, item := range tests {
		enc, err := EncodeTxDAG(item.expect)
		t.Log(hex.EncodeToString(enc))
		require.NoError(t, err, i)
		actual, err := DecodeTxDAG(enc)
		require.NoError(t, err, i)
		require.Equal(t, item.expect, actual, i)
		if i%2 == 0 {
			enc[0] = 2
			_, err = DecodeTxDAG(enc)
			require.Error(t, err)
		}
	}
}

func TestDecodeTxDAG(t *testing.T) {
	tests := []struct {
		enc string
		err bool
	}{
		{"00c0", false},
		{"01dddcc1c0c1c0c1c0c2c180c2c180c3c20102c3c20205c2c106c1c0c2c108", false},
		{"01e3e2c1c0c1c0c1c0c2c180c2c180c3c20102c3c20205c2c106c1c0c2c108c2c001c2c001", false},
		{"0132e212", true},
		{"01dfdec280c0c280c0c380c101c380c102c380c103c380c104c380c105c380c106", true},
		{"01cdccc280c0c280c0c280c0c280c0", true},
	}
	for i, item := range tests {
		enc, err := hex.DecodeString(item.enc)
		require.NoError(t, err, i)
		txDAG, err := DecodeTxDAG(enc)
		if item.err {
			require.Error(t, err, i)
			continue
		}
		require.NoError(t, err, i)
		t.Log(txDAG)
	}
}

func TestTxDep_Flags(t *testing.T) {
	dep := NewTxDep(nil)
	dep.ClearFlag(NonDependentRelFlag)
	dep.SetFlag(NonDependentRelFlag)
	dep.SetFlag(ExcludedTxFlag)
	compared := NewTxDep(nil, NonDependentRelFlag, ExcludedTxFlag)
	require.Equal(t, dep, compared)
	require.Equal(t, NonDependentRelFlag|ExcludedTxFlag, *dep.Flags)
	dep.ClearFlag(ExcludedTxFlag)
	require.Equal(t, NonDependentRelFlag, *dep.Flags)
	require.True(t, dep.CheckFlag(NonDependentRelFlag))
	require.False(t, dep.CheckFlag(ExcludedTxFlag))
}
